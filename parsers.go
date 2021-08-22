package libinjection

import (
	"bytes"
	"fmt"
	"unicode"
)

func parse_slash(sf *libinjection_sqli_state) int {
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos
	cur := pos
	ctype := TYPE_COMMENT
	pos1 := pos + 1
	var clen int
	if pos1 == slen || cs[pos1] != '*' {
		return parse_operator1(sf)
	}

	/*
	 * skip over initial '/x'
	 */
	ptr := bytes.IndexAny(cs[cur+2:slen-(pos+2)], "/*")
	if ptr == -1 {
		/* till end of line */
		clen = slen - pos
	} else {
		clen = ptr + 2 - cur
	}

	/*
	 * postgresql allows nested comments which makes
	 * this is incompatible with parsing so
	 * if we find a '/x' inside the coment, then
	 * make a new token.
	 *
	 * Also, Mysql's "conditional" comments for version
	 *  are an automatic black ban!
	 */

	if ptr != -1 && bytes.ContainsAny(cs[cur+2:(ptr-(cur+1))], "/*") {
		ctype = TYPE_EVIL
	} else if is_mysql_comment(cs, slen, pos) {
		ctype = TYPE_EVIL
	}

	sf.Current.Assign(byte(ctype), pos, clen, cs[pos:])
	return pos + clen
}

func parse_backslash(sf *libinjection_sqli_state) int {
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	/*
	 * Weird MySQL alias for NULL, "\N" (capital N only)
	 */
	if pos+1 < slen && cs[pos+1] == 'N' {
		sf.Current.Assign(TYPE_NUMBER, pos, 2, cs[pos:])
		return pos + 2
	} else {
		sf.Current.Assign_char(TYPE_BACKSLASH, pos, 1, cs[pos])
		return pos + 1
	}
}

func parse_operator2(sf *libinjection_sqli_state) int {
	var ch byte
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	if pos+1 >= slen {
		return parse_operator1(sf)
	}

	if pos+2 < slen &&
		cs[pos] == '<' &&
		cs[pos+1] == '=' &&
		cs[pos+2] == '>' {
		/*
		 * special 3-char operator
		 */
		sf.Current.Assign(TYPE_OPERATOR, pos, 3, cs[pos:])
		return pos + 3
	}

	ch = sf.Lookup(LOOKUP_OPERATOR, cs[pos:], 2)
	if ch != CHAR_NULL {
		sf.Current.Assign(ch, pos, 2, cs[pos:])
		return pos + 2
	}

	/*
	 * not an operator.. what to do with the two
	 * characters we got?
	 */

	if cs[pos] == ':' {
		/* ':' is not an operator */
		sf.Current.Assign(TYPE_COLON, pos, 1, cs[pos:])
		return pos + 1
	} else {
		/*
		 * must be a single char operator
		 */
		return parse_operator1(sf)
	}
}

/** In ANSI mode, hash is an operator
 *  In MYSQL mode, it's a EOL comment like '--'
 */
func parse_hash(sf *libinjection_sqli_state) int {
	sf.Stats_comment_hash += 1
	//TODO check
	if sf.Flags&FLAG_SQL_MYSQL == 1 {
		sf.Stats_comment_hash += 1
		return parse_eol_comment(sf)
	} else {
		sf.Current.Assign_char(TYPE_OPERATOR, sf.Pos, 1, '#')
		return sf.Pos + 1
	}
}

func parse_dash(sf *libinjection_sqli_state) int {
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	/*
	 * five cases
	 * 1) --[white]  this is always a SQL comment
	 * 2) --[EOF]    this is a comment
	 * 3) --[notwhite] in MySQL this is NOT a comment but two unary operators
	 * 4) --[notwhite] everyone else thinks this is a comment
	 * 5) -[not dash]  '-' is a unary operator
	 */

	if pos+2 < slen && cs[pos+1] == '-' && char_is_white(cs[pos+2]) {
		return parse_eol_comment(sf)
	} else if pos+2 == slen && cs[pos+1] == '-' {
		return parse_eol_comment(sf)
		//TODO check:
	} else if pos+1 < slen && cs[pos+1] == '-' && (sf.Flags&FLAG_SQL_ANSI == 1) {
		/* --[not-white] not-white case:
		 *
		 */
		sf.Stats_comment_ddx += 1
		return parse_eol_comment(sf)
	} else {
		sf.Current.Assign_char(TYPE_OPERATOR, pos, 1, '-')
		return pos + 1
	}
}

func parse_white(sf *libinjection_sqli_state) int {
	return sf.Pos + 1
}

func parse_operator1(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos

	sf.Current.Assign_char(TYPE_OPERATOR, pos, 1, cs[pos])
	return pos + 1
}

func parse_other(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos

	sf.Current.Assign_char(TYPE_UNKNOWN, pos, 1, cs[pos])
	return pos + 1
}

func parse_char(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos

	sf.Current.Assign_char(cs[pos], pos, 1, cs[pos])
	return pos + 1
}

//TODO this might be all wrong
func parse_eol_comment(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos
	slen := sf.Slen

	endpos := bytes.IndexByte(cs[pos:pos+slen], '\n')
	if endpos == -1 {
		sf.Current.Assign(TYPE_COMMENT, pos, slen-pos, cs[pos:])
		return slen
	} else {
		sf.Current.Assign(TYPE_COMMENT, pos, endpos-pos, cs[pos:])
		//return ((endpos - cs) + 1)
		return 0
	}
}

/* Look forward for doubling of delimiter
 *
 * case 'foo''bar' -. foo''bar
 *
 * ending quote isn't duplicated (i.e. escaped)
 * since it's the wrong char or EOL
 *
 */
func parse_string_core(cs []byte, l int, pos int, st *stoken_t, delim byte, offset int) int {
	/*
	 * offset is to skip the perhaps first quote char
	 */
	// super maths!
	qpos := pos + offset + bytes.IndexByte(cs[pos+offset:(l-pos-offset)+(pos+offset)], delim)

	/*
	 * then keep string open/close info
	 */
	if offset > 0 {
		/*
		 * this is real quote
		 */
		st.StrOpen = delim
	} else {
		/*
		 * this was a simulated quote
		 */
		st.StrOpen = CHAR_NULL
	}

	for {
		if qpos == -1 {
			/*
			 * string ended with no trailing quote
			 * assign what we have
			 */
			st.Assign(TYPE_STRING, pos+offset, l-pos-offset, cs[pos+offset:])
			st.StrClose = CHAR_NULL
			return l
		} else if is_backslash_escaped(cs[qpos-1:]) {
			/* keep going, move ahead one character */
			qpos = bytes.IndexByte(cs[qpos+1:qpos+1+(l-(qpos+1))], delim)
			continue
		} else if is_double_delim_escaped(cs[qpos:]) {
			/* keep going, move ahead two characters */
			qpos = bytes.IndexByte(cs[qpos+2:qpos+2+(l-(qpos+2))], delim)
			continue
		} else {
			/* hey it's a normal string */
			st.Assign(TYPE_STRING, pos+offset, qpos-(pos+offset), cs[pos+offset:])
			st.StrClose = delim
			return qpos + 1
		}
	}
}

/**
 * Used when first char is a ' or "
 */
func parse_string(sf *libinjection_sqli_state) int {
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	/*
	 * assert cs[pos] == single or double quote
	 */
	return parse_string_core(cs, slen, pos, sf.Current, cs[pos], 1)
}

/**
 * Used when first char is:
 *    N or n:  mysql "National Character set"
 *    E     :  psql  "Escaped String"
 */
func parse_estring(sf *libinjection_sqli_state) int {
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	if pos+2 >= slen || cs[pos+1] != CHAR_SINGLE {
		return parse_word(sf)
	}
	return parse_string_core(cs, slen, pos, sf.Current, CHAR_SINGLE, 2)
}

func parse_ustring(sf *libinjection_sqli_state) int {
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	if pos+2 < slen && cs[pos+1] == '&' && cs[pos+2] == '\'' {
		sf.Pos += 2
		pos = parse_string(sf)
		sf.Current.StrOpen = 'u'
		if sf.Current.StrClose == '\'' {
			sf.Current.StrClose = 'u'
		}
		return pos
	} else {
		return parse_word(sf)
	}
}

func parse_qstring_core(sf *libinjection_sqli_state, offset int) int {
	var ch byte
	var strend int
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	/* if we are already at end of string..
	   if current char is not q or Q
	   if we don't have 2 more chars
	   if char2 != a single quote
	   then, just treat as word
	*/
	if pos >= slen ||
		(cs[pos] != 'q' && cs[pos] != 'Q') ||
		pos+2 >= slen ||
		cs[pos+1] != '\'' {
		return parse_word(sf)
	}

	ch = cs[pos+2]

	/* the ch > 127 is un-needed since
	 * we assume char is signed
	 */
	if ch < 33 /* || ch > 127 */ {
		return parse_word(sf)
	}
	switch ch {
	case '(':
		ch = ')'
	case '[':
		ch = ']'
	case '{':
		ch = '}'
	case '<':
		ch = '>'
	}

	strend = bytes.IndexAny(cs[pos+3:slen+pos+3], string([]byte{ch, '\''}))
	if strend == -1 {
		sf.Current.Assign(TYPE_STRING, pos+3, slen-pos-3, cs[pos+3:])
		sf.Current.StrOpen = 'q'
		sf.Current.StrClose = CHAR_NULL
		return slen
	} else {
		sf.Current.Assign(TYPE_STRING, pos+3, strend-pos-3, cs[pos+3:])
		sf.Current.StrOpen = 'q'
		sf.Current.StrClose = 'q'
		return strend + 2
	}
}

/*
 * Oracle's q string
 */
func parse_qstring(sf *libinjection_sqli_state) int {
	return parse_qstring_core(sf, 0)
}

/*
 * mysql's N'STRING' or
 * ...  Oracle's nq string
 */
func parse_nqstring(sf *libinjection_sqli_state) int {
	slen := sf.Slen
	pos := sf.Pos
	if pos+2 < slen && sf.S[pos+1] == CHAR_SINGLE {
		return parse_estring(sf)
	}
	return parse_qstring_core(sf, 1)
}

/*
 * binary literal string
 * re: [bB]'[01]*'
 */
func parse_bstring(sf *libinjection_sqli_state) int {
	var wlen int
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	/* need at least 2 more characters
	 * if next char isn't a single quote, then
	 * continue as normal word
	 */
	if pos+2 >= slen || cs[pos+1] != '\'' {
		return parse_word(sf)
	}

	wlen = strlenspn(cs[pos+2:], sf.Slen-pos-2, "01")
	if pos+2+wlen >= slen || cs[pos+2+wlen] != '\'' {
		return parse_word(sf)
	}
	sf.Current.Assign(TYPE_NUMBER, pos, wlen+3, cs[pos:])
	return pos + 2 + wlen + 1
}

/*
 * hex literal string
 * re: [xX]'[0123456789abcdefABCDEF]*'
 * mysql has requirement of having EVEN number of chars,
 *  but pgsql does not
 */
func parse_xstring(sf *libinjection_sqli_state) int {
	var wlen int
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos

	/* need at least 2 more characters
	 * if next char isn't a single quote, then
	 * continue as normal word
	 */
	if pos+2 >= slen || cs[pos+1] != '\'' {
		return parse_word(sf)
	}

	wlen = strlenspn(cs[pos+2:], sf.Slen-pos-2, "0123456789ABCDEFabcdef")
	if pos+2+wlen >= slen || cs[pos+2+wlen] != '\'' {
		return parse_word(sf)
	}
	sf.Current.Assign(TYPE_NUMBER, pos, wlen+3, cs[pos:])
	return pos + 2 + wlen + 1
}

/**
 * This handles MS SQLSERVER bracket words
 * http://stackoverflow.com/questions/3551284/sql-serverwhat-do-brackets-mean-around-column-name
 *
 */
func parse_bword(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos
	endptr := bytes.IndexByte(cs[pos:pos+(sf.Slen-pos)], ']')
	if endptr == -1 {
		sf.Current.Assign(TYPE_BAREWORD, pos, sf.Slen-pos, cs[pos:])
		return sf.Slen
	} else {
		sf.Current.Assign(TYPE_BAREWORD, pos, endptr-pos+1, cs[pos:])
		return endptr + 1
	}
}

func parse_word(sf *libinjection_sqli_state) int {
	var ch, delim byte
	cs := sf.S
	pos := sf.Pos
	wlen := strlencspn(cs[pos:], sf.Slen-pos, " []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r\"\240\000")

	sf.Current.Assign(TYPE_BAREWORD, pos, wlen, cs[pos:])

	/* now we need to look inside what we good for "." and "`"
	 * and see if what is before is a keyword or not
	 */
	fmt.Println(sf.Current.Len, sf.Current.Val)
	for i := 0; i < len(sf.Current.Val); i++ {
		delim = sf.Current.Val[i]
		if delim == '.' || delim == '`' {
			ch = sf.Lookup(LOOKUP_WORD, sf.Current.Val, i)
			if ch != TYPE_NONE && ch != TYPE_BAREWORD {
				/* needed for swig */
				sf.Current = nil
				/*
				 * we got something like "SELECT.1"
				 * or SELECT`column`
				 */
				sf.Current.Assign(ch, pos, i, cs[pos:])
				return pos + i
			}
		}
	}

	/*
	 * do normal lookup with word including '.'
	 */
	if wlen < LIBINJECTION_SQLI_TOKEN_SIZE {

		ch = sf.Lookup(LOOKUP_WORD, sf.Current.Val, wlen)
		if ch == CHAR_NULL {
			ch = TYPE_BAREWORD
		}
		sf.Current.Type = ch
	}
	return pos + wlen
}

/* MySQL backticks are a cross between string and
 * and a bare word.
 *
 */
func parse_tick(sf *libinjection_sqli_state) int {
	pos := parse_string_core(sf.S, sf.Slen, sf.Pos, sf.Current, CHAR_TICK, 1)

	/* we could check to see if start and end of
	 * of string are both "`", i.e. make sure we have
	 * matching set.  `foo` vs. `foo
	 * but I don't think it matters much
	 */

	/* check value of string to see if it's a keyword,
	 * function, operator, etc
	 */
	ch := sf.Lookup(LOOKUP_WORD, sf.Current.Val, sf.Current.Len)
	if ch == TYPE_FUNCTION {
		/* if it's a function, then convert token */
		sf.Current.Type = TYPE_FUNCTION
	} else {
		/* otherwise it's a 'n' type -- mysql treats
		 * everything as a bare word
		 */
		sf.Current.Type = TYPE_BAREWORD
	}
	return pos
}

func parse_var(sf *libinjection_sqli_state) int {
	var xlen int
	cs := sf.S
	slen := sf.Slen
	pos := sf.Pos + 1

	/*
	 * var_count is only used to reconstruct
	 * the input.  It counts the number of '@'
	 * seen 0 in the case of NULL, 1 or 2
	 */

	/*
	 * move past optional other '@'
	 */
	if pos < slen && cs[pos] == '@' {
		pos += 1
		sf.Current.Count = 2
	} else {
		sf.Current.Count = 1
	}

	/*
	 * MySQL allows @@`version`
	 */
	if pos < slen {
		if cs[pos] == '`' {
			sf.Pos = pos
			pos = parse_tick(sf)
			sf.Current.Type = TYPE_VARIABLE
			return pos
		} else if cs[pos] == CHAR_SINGLE || cs[pos] == CHAR_DOUBLE {
			sf.Pos = pos
			pos = parse_string(sf)
			sf.Current.Type = TYPE_VARIABLE
			return pos
		}
	}

	xlen = strlencspn(cs[pos:], slen-pos, " <>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r'`\"")
	if xlen == 0 {
		sf.Current.Assign(TYPE_VARIABLE, pos, 0, cs[pos:])
		return pos
	} else {
		sf.Current.Assign(TYPE_VARIABLE, pos, xlen, cs[pos:])
		return pos + xlen
	}
}

func parse_money(sf *libinjection_sqli_state) int {
	var xlen, strend int
	cs := sf.S
	pos := sf.Pos
	slen := sf.Slen

	if pos+1 == slen {
		/* end of line */
		sf.Current.Assign_char(TYPE_BAREWORD, pos, 1, '$')
		return slen
	}

	/*
	 * $1,000.00 or $1.000,00 ok!
	 * This also parses $....,,,111 but that's ok
	 */

	xlen = strlenspn(cs[pos+1:], slen-pos-1, "0123456789.,")
	if xlen == 0 {
		if cs[pos+1] == '$' {
			/* we have $$ .. find ending $$ and make string */
			//TODO check
			strend = bytes.IndexAny(cs[pos+2:], string("$$"))
			if strend == -1 {
				/* fell off edge */
				sf.Current.Assign(TYPE_STRING, pos+2, slen-(pos+2), cs[pos+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = CHAR_NULL
				return slen
			} else {
				sf.Current.Assign(TYPE_STRING, pos+2, (strend - pos + 2), cs[pos+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = '$'
				return strend + 2
			}
		} else {
			/* ok it's not a number or '$$', but maybe it's pgsql "$ quoted strings" */
			xlen = strlenspn(cs[pos+1:], slen-pos-1, "abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if xlen == 0 {
				/* hmm it's "$" _something_ .. just add $ and keep going*/
				sf.Current.Assign_char(TYPE_BAREWORD, pos, 1, '$')
				return pos + 1
			}
			/* we have $foobar????? */
			/* is it $foobar$ */
			if pos+xlen+1 == slen || cs[pos+xlen+1] != '$' {
				/* not $foobar$, or fell off edge */
				sf.Current.Assign_char(TYPE_BAREWORD, pos, 1, '$')
				return pos + 1
			}

			/* we have $foobar$ ... find it again */
			strend = bytes.IndexAny(cs[pos+xlen+2:], string(cs[pos:pos+xlen+2]))

			// TODO check
			if strend > slen {
				/* fell off edge */
				sf.Current.Assign(TYPE_STRING, pos+xlen+2, slen-pos-xlen-2, cs[pos+xlen+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = CHAR_NULL
				return slen
			} else {
				/* got one */
				sf.Current.Assign(TYPE_STRING, pos+xlen+2, (strend - pos + xlen + 2), cs[pos+xlen+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = '$'
				return strend + xlen + 2
			}
		}
	} else if xlen == 1 && cs[pos+1] == '.' {
		/* $. should parsed as a word */
		return parse_word(sf)
	} else {
		sf.Current.Assign(TYPE_NUMBER, pos, 1+xlen, cs[pos:])
		return pos + 1 + xlen
	}
}

func parse_number(sf *libinjection_sqli_state) int {
	var xlen, start, have_e, have_exp int
	var digits string
	cs := sf.S
	pos := sf.Pos
	slen := sf.Slen

	/* cs[pos] == '0' has 1/10 chance of being true,
	 * while pos+1< slen is almost always true
	 */
	if cs[pos] == '0' && pos+1 < slen {
		if cs[pos+1] == 'X' || cs[pos+1] == 'x' {
			digits = "0123456789ABCDEFabcdef"
		} else if cs[pos+1] == 'B' || cs[pos+1] == 'b' {
			digits = "01"
		}

		if digits != "" {
			xlen = strlenspn(cs[pos+2:], slen-pos-2, digits)
			if xlen == 0 {
				sf.Current.Assign(TYPE_BAREWORD, pos, 2, cs[pos:])
				return pos + 2
			} else {
				sf.Current.Assign(TYPE_NUMBER, pos, 2+xlen, cs[pos:])
				return pos + 2 + xlen
			}
		}
	}

	start = pos
	for pos < slen && unicode.IsDigit(rune(cs[pos])) {
		pos += 1
	}

	if pos < slen && cs[pos] == '.' {
		pos += 1
		for pos < slen && unicode.IsDigit(rune(cs[pos])) {
			pos += 1
		}
		if pos-start == 1 {
			/* only one character read so far */
			sf.Current.Assign_char(TYPE_DOT, start, 1, '.')
			return pos
		}
	}

	if pos < slen {
		if cs[pos] == 'E' || cs[pos] == 'e' {
			have_e = 1
			pos += 1
			if pos < slen && (cs[pos] == '+' || cs[pos] == '-') {
				pos += 1
			}
			for pos < slen && unicode.IsDigit(rune(cs[pos])) {
				have_exp = 1
				pos += 1
			}
		}
	}

	/* oracle's ending float or double suffix
	 * http://docs.oracle.com/cd/B19306_01/server.102/b14200/sql_elements003.htm#i139891
	 */
	if pos < slen && (cs[pos] == 'd' || cs[pos] == 'D' || cs[pos] == 'f' || cs[pos] == 'F') {
		if pos+1 == slen {
			/* line ends evaluate "... 1.2f$" as '1.2f' */
			pos += 1
		} else if char_is_white(cs[pos+1]) || cs[pos+1] == ';' {
			/*
			 * easy case, evaluate "... 1.2f ... as '1.2f'
			 */
			pos += 1
		} else if cs[pos+1] == 'u' || cs[pos+1] == 'U' {
			/*
			 * a bit of a hack but makes '1fUNION' parse as '1f UNION'
			 */
			pos += 1
		} else {
			/* it's like "123FROM" */
			/* parse as "123" only */
		}
	}

	if have_e == 1 && have_exp == 0 {
		/* very special form of
		 * "1234.e"
		 * "10.10E"
		 * ".E"
		 * this is a WORD not a number!! */
		sf.Current.Assign(TYPE_BAREWORD, start, pos-start, cs[start:])
	} else {
		sf.Current.Assign(TYPE_NUMBER, start, pos-start, cs[start:])
	}
	return pos
}
