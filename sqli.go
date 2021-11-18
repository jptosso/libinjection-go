package libinjection

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	//flags
	FLAG_NONE         = 0
	FLAG_QUOTE_NONE   = 1  /* 1 << 0 */
	FLAG_QUOTE_SINGLE = 2  /* 1 << 1 */
	FLAG_QUOTE_DOUBLE = 4  /* 1 << 2 */
	FLAG_SQL_ANSI     = 8  /* 1 << 3 */
	FLAG_SQL_MYSQL    = 16 /* 1 << 4 */

	//types
	TYPE_NONE           = 0x00
	TYPE_KEYWORD        = 'k'
	TYPE_UNION          = 'U'
	TYPE_GROUP          = 'B'
	TYPE_EXPRESSION     = 'E'
	TYPE_SQLTYPE        = 't'
	TYPE_FUNCTION       = 'f'
	TYPE_BAREWORD       = 'n'
	TYPE_NUMBER         = '1'
	TYPE_VARIABLE       = 'v'
	TYPE_STRING         = 's'
	TYPE_OPERATOR       = 'o'
	TYPE_LOGIC_OPERATOR = '&'
	TYPE_COMMENT        = 'c'
	TYPE_COLLATE        = 'A'
	TYPE_LEFTPARENS     = '('
	TYPE_RIGHTPARENS    = ')' /* not used? */
	TYPE_LEFTBRACE      = '{'
	TYPE_RIGHTBRACE     = '}'
	TYPE_DOT            = '.'
	TYPE_COMMA          = ','
	TYPE_COLON          = ':'
	TYPE_SEMICOLON      = ';'
	TYPE_TSQL           = 'T' /* TSQL start */
	TYPE_UNKNOWN        = '?'
	TYPE_EVIL           = 'X' /* unparsable, abort  */
	TYPE_FINGERPRINT    = 'F' /* not really a token */
	TYPE_BACKSLASH      = '\\'

	//chars
	CHAR_NULL   = 0x00 // \0
	CHAR_SINGLE = '\''
	CHAR_DOUBLE = '"'
	CHAR_TICK   = '`'

	LIBINJECTION_SQLI_TOKEN_SIZE = 32
	LIBINJECTION_SQLI_MAX_TOKENS = 5
	LIBINJECTION_VERSION         = "3.9.2"

	LOOKUP_WORD        = 1
	LOOKUP_TYPE        = 2
	LOOKUP_OPERATOR    = 3
	LOOKUP_FINGERPRINT = 4
)

type Sqli struct {
	state *State
}

func (sqli *Sqli) parse_number() int {
	var xlen int
	var start int
	digits := ""
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos
	have_e := false
	have_exp := false

	/*
	 * s[pos] == '0' has 1/10 chance of being true, while pos+1< slen
	 * is almost always true
	 */
	if s[pos] == '0' && pos+1 < slen {
		if s[pos+1] == 'X' || s[pos+1] == 'x' {
			digits = "0123456789ABCDEFabcdef"
		} else if s[pos+1] == 'B' || s[pos+1] == 'b' {
			digits = "01"
		}

		if digits != "" {
			xlen = strlenspn(s[pos+2:], digits)
			if xlen == 0 {
				token := newToken(TYPE_BAREWORD, pos, 2, "0"+string(s[pos+1]))
				state.tokenvec[state.current] = token
				return pos + 2
			} else {
				token := newToken(TYPE_NUMBER, pos, 2+xlen, s[pos:pos+1+xlen+1])
				state.tokenvec[state.current] = token
				return pos + 1 + xlen + 1
			}
		}
	}

	start = pos
	for pos < slen && unicode.IsDigit(rune(s[pos])) {
		pos += 1
	}

	/* number sequence reached a '.' */
	if pos < slen && s[pos] == '.' {
		pos += 1
		/* keep going since it might be decimal */
		for pos < slen && unicode.IsDigit(rune(s[pos])) {
			pos += 1
		}
		if pos-start == 1 {
			/* only one character '.' read so far */
			state.tokenvec[state.current] = newToken(TYPE_DOT, start, 1, ".")
			return pos
		}
	}

	if pos < slen {
		if s[pos] == 'E' || s[pos] == 'e' {
			have_e = true
			pos += 1
			if pos < slen && (s[pos] == '+' || s[pos] == '-') {
				pos += 1
			}
			for pos < slen && unicode.IsDigit(rune(s[pos])) {
				have_exp = true
				pos += 1
			}
		}
	}

	/*
	 * oracle's ending float or double suffix
	 * http://docs.oracle.com/cd/B19306_01/server.102/b14200/sql_elements003
	 * .htm#i139891
	 */
	if pos < slen && (s[pos] == 'd' || s[pos] == 'D' || s[pos] == 'f' || s[pos] == 'F') {
		if pos+1 == slen {
			/* line ends evaluate "... 1.2f$" as '1.2f' */
			pos += 1
		} else if char_is_white(s[pos+1]) || s[pos+1] == ';' {
			/*
			 * easy case, evaluate "... 1.2f ... as '1.2f'
			 */
			pos += 1
		} else if s[pos+1] == 'u' || s[pos+1] == 'U' {
			/*
			 * a bit of a hack but makes '1fUNION' parse as '1f UNION'
			 */
			pos += 1
		} else {
			/* it's like "123FROM" */
			/* parse as "123" only */
		}
	}

	if have_e && !have_exp {
		/*
		 * very special form of "1234.e" "10.10E" ".E" this is a WORD not a
		 * number!!
		 */
		state.tokenvec[state.current] = newToken(TYPE_BAREWORD, start, pos-start, s[start:pos])
	} else {
		state.tokenvec[state.current] = newToken(TYPE_NUMBER, start, pos-start, s[start:pos])
	}
	return pos
}

func (sqli *Sqli) parse_money() int {
	var xlen int
	var strend int
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos

	if pos+1 == slen {
		/* end of line */
		state.tokenvec[state.current] = newToken(TYPE_BAREWORD, pos, 1, "$")
		return slen
	}

	/*
	 * $1,000.00 or $1.000,00 ok! This also parses $....,,,111 but that's ok
	 */
	xlen = strlenspn(s[pos+1:], "0123456789.,")
	if xlen == 0 {
		if s[pos+1] == '$' {
			/* we have $$ .. find ending $$ and make string */
			strend = strings.Index(s[pos+2:], "$$")
			if strend == -1 {
				/* fell off edge: $$ not found */
				token := newToken(TYPE_STRING, pos+2, slen-(pos+2), s[pos+2:])
				token.str_open = '$'
				token.str_close = CHAR_NULL
				state.tokenvec[state.current] = token
				return slen
			} else {
				token := newToken(TYPE_STRING, pos+2, strend-(pos+2), s[pos+2:strend])
				token.str_open = '$'
				token.str_close = '$'
				state.tokenvec[state.current] = token
				return strend + 2
			}
		} else {
			/* it's not '$$', but maybe it's pgsql "$ quoted strings" */
			xlen = strlenspn(s[pos+1:], "abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if xlen == 0 {
				/* hmm it's "$" _something_ .. just add $ and keep going */
				token := newToken(TYPE_BAREWORD, pos, 1, "$")
				state.tokenvec[state.current] = token
				return pos + 1
			} else {
				/* we have $foobar????? */
				/* is it $foobar$ */
				if pos+xlen+1 == slen || s[pos+xlen+1] != '$' {
					/* not $foobar$, or fell off edge */
					token := newToken(TYPE_BAREWORD, pos, 1, "$")
					state.tokenvec[state.current] = token
					return pos + 1
				}

				/* we have $foobar$... find it again */
				strend = strings.Index(s[pos+xlen+2:], s[pos:pos+xlen+2])

				if strend == -1 || strend < pos+xlen+2 {
					/* fell off edge */
					token := newToken(TYPE_STRING, pos+xlen+2, slen-pos-xlen-2, s[pos+xlen+2:])
					token.str_open = '$'
					token.str_close = CHAR_NULL
					state.tokenvec[state.current] = token
					return slen
				} else {
					/*
					 * got one. we're looking in between
					 * $foobar$__________$foobar$
					 */
					token := newToken(TYPE_STRING, pos+xlen+2, strend-pos-xlen-2, s[pos+xlen+2:strend])
					token.str_open = '$'
					token.str_close = '$'
					state.tokenvec[state.current] = token
					return strend + xlen + 2
				}
			}
		}
	} else if xlen == 1 && s[pos+1] == '.' {
		/* $. should be parsed as a word */
		return sqli.parse_word()
	} else {
		token := newToken(TYPE_NUMBER, pos, 1+xlen, s[pos:pos+xlen+1])
		state.tokenvec[state.current] = token
		return pos + xlen + 1
	}
}

func (sqli *Sqli) parse_var() int {
	var xlen int
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos + 1

	/*
	 * var_count is only used to reconstruct the input. It counts the number
	 * of '@' seen 0 in the case of NULL, 1 or 2
	 */

	/*
	 * move past optional other '@'
	 */
	if pos < slen && s[pos] == '@' {
		pos += 1
		state.tokenvec[state.current].count = 2
	} else {
		state.tokenvec[state.current].count = 1
	}

	/*
	 * MySQL allows @@`version`
	 */
	if pos < slen {
		if s[pos] == '`' {
			state.pos = pos
			pos = sqli.parse_tick()
			state.tokenvec[state.current].Type = TYPE_VARIABLE
			return pos
		} else if s[pos] == CHAR_SINGLE || s[pos] == CHAR_DOUBLE {
			state.pos = pos
			pos = sqli.parse_string()
			state.tokenvec[state.current].Type = TYPE_VARIABLE
			return pos
		}
	}

	xlen = strlencspn(s[pos:], " <>:\\?=@!#~+-*/&|^%(),';\t\n\u000b\f\r'`\"")
	if xlen == 0 {
		token := newToken(TYPE_VARIABLE, pos, 0, "")
		state.tokenvec[state.current] = token
		return pos
	} else {
		token := newToken(TYPE_VARIABLE, pos, xlen, s[pos:pos+xlen])
		state.tokenvec[state.current] = token
		return pos + xlen
	}
}

func (sqli *Sqli) parse_tick() int {
	pos := sqli.parse_string_core(CHAR_TICK, 1)
	state := sqli.state

	/*
	 * we could check to see if start and end of of string are both "`",
	 * i.e. make sure we have matching set. `foo` vs. `foo but I don't think
	 * it matters much
	 */

	/*
	 * check value of string to see if it's a keyword, function, operator,
	 * etc
	 */
	wordtype := libinjection_sqli_lookup_word(state.tokenvec[state.current].val)
	if wordtype != 0 && wordtype == TYPE_FUNCTION {
		/* if it's a function, then convert to token */
		state.tokenvec[state.current].Type = TYPE_FUNCTION
	} else {
		/*
		 * otherwise it's a 'n' type -- mysql treats everything as a bare
		 * word
		 */
		state.tokenvec[state.current].Type = TYPE_BAREWORD
	}
	return pos
}

func (sqli *Sqli) parse_word() int {
	var wordtype byte
	var delim byte
	state := sqli.state
	s := state.s
	pos := state.pos

	unaccepted := " []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\f\r\"\240\000\u000b" // \u000b is vertical tab
	str := s[pos:]
	wlen := strlencspn(str, unaccepted)
	word := s[pos : pos+wlen]

	token := newToken(TYPE_BAREWORD, pos, wlen, word)
	state.tokenvec[state.current] = token

	/*
	 * look for characters before "." and "`" and see if they're keywords
	 */
	for i := 0; i < token.Len; i++ {
		delim = token.val[i]
		if delim == '.' || delim == '`' {
			wordtype = libinjection_sqli_lookup_word(word[:i])
			if wordtype != 0x00 && wordtype != TYPE_NONE && wordtype != TYPE_BAREWORD {
				/*
				 * we got something like "SELECT.1" or SELECT`column`
				 */
				state.tokenvec[state.current] = newToken(int(wordtype), pos, i, word[:i])
				return pos + i
			}
		}
	}

	/*
	 * do normal lookup with word including '.'
	 */
	wordtype = libinjection_sqli_lookup_word(token.val)
	/*
	 * before, we differentiated fingerprint lookups from word lookups
	 * by adding a 0 to the front for fingerprint lookups.
	 * now, just check if word we found was a fingerprint
	 */
	if wordtype == 0 || wordtype == 'F' {
		wordtype = TYPE_BAREWORD
	}
	state.tokenvec[state.current].Type = wordtype

	return pos + wlen
}

/*
 * This handles MS SQLSERVER bracket words
 * http://stackoverflow.com/questions/3551284/sql-serverwhat-do-brackets-
 * mean-around-column-name
 */
func (sqli *Sqli) parse_bword() int {
	state := sqli.state
	s := state.s
	pos := state.pos
	slen := state.slen
	endptr := strings.IndexByte(s[pos:], ']')
	if endptr == -1 {
		token := newToken(TYPE_BAREWORD, pos, slen-pos, s[pos:])
		state.tokenvec[state.current] = token
		return state.slen
	} else {
		token := newToken(TYPE_BAREWORD, pos, endptr+1-pos, s[pos:endptr+1])
		state.tokenvec[state.current] = token
		return endptr + 1
	}
}

/*
 * hex literal string re: [xX]'[0123456789abcdefABCDEF]*' mysql has
 * requirement of having EVEN number of chars, but pgsql does not
 */
func (sqli *Sqli) parse_xstring() int {
	state := sqli.state
	wlen := 0
	s := state.s
	pos := state.pos
	slen := state.slen

	/*
	 * need at least 2 more characters if next char isn't a single quote,
	 * then continue as normal word
	 */
	if pos+2 >= slen || s[pos+1] != '\'' {
		return sqli.parse_word()
	}
	wlen = strlenspn(s[pos+2:], "0123456789abcdefABCDEF")

	/*
	 * if [0123456789abcdefABCDEF]* pattern not found,
	 * or the pattern did not close with a single quote
	 */
	if pos+2+wlen >= slen || s[pos+2+wlen] != '\'' {
		return sqli.parse_word()
	}

	/* +3 for [xX], starting quote, ending quote */
	token := newToken(TYPE_NUMBER, pos, wlen+3, s[pos:pos+wlen+3])
	state.tokenvec[state.current] = token
	return pos + 2 + wlen + 1
}

/*
 * binary literal string re: [bB]'[01]*'
 */
func (sqli *Sqli) parse_bstring() int {
	wlen := 0
	state := sqli.state
	s := state.s
	pos := state.pos
	slen := state.slen

	/*
	 * need at least 2 more characters if next char isn't a single quote,
	 * then continue as normal word
	 */
	if pos+2 >= slen || s[pos+1] != '\'' {
		return sqli.parse_word()
	}
	wlen = strlenspn(s[pos+2:], "01")

	/*
	 * if [01]* pattern not found, or the pattern
	 * did not close with a single quote
	 */
	if pos+2+wlen >= slen || s[pos+2+wlen] != '\'' {
		return sqli.parse_word()
	}

	/* +3 for [bB], starting quote, ending quote */
	token := newToken(TYPE_NUMBER, pos, wlen+3, s[pos:pos+wlen+3])
	state.tokenvec[state.current] = token
	return pos + 2 + wlen + 1
}

/*
 * mysql's N'STRING' or ... Oracle's nq string
 */
func (sqli *Sqli) parse_nqstring() int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos
	if pos+2 < slen && s[pos+1] == CHAR_SINGLE {
		return sqli.parse_estring()
	}
	return sqli.parse_qstring_core(1)
}

/*
 * Oracle's q string
 */
func (sqli *Sqli) parse_qstring() int {
	return sqli.parse_qstring_core(0)
}

func (sqli *Sqli) parse_qstring_core(offset int) int {
	var ch byte
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos + offset

	/*
	 * if we are already at end of string.. if current char is not q or Q if
	 * we don't have 2 more chars if char2 != a single quote then, just
	 * treat as word
	 */
	if pos >= slen || (s[pos] != 'q' && s[pos] != 'Q') || pos+2 >= slen || s[pos+1] != '\'' {
		return sqli.parse_word()
	}
	ch = s[pos+2]

	/*
	 * the ch > 127 is un-needed since we assume char is signed
	 */
	if ch < 33 /* || ch > 127 */ {
		return sqli.parse_word()
	}
	switch ch {
	case '(':
		ch = ')'
		break
	case '[':
		ch = ']'
		break
	case '{':
		ch = '}'
		break
	case '<':
		ch = '>'
		break
	}

	/* find )' or ]' or }' or >' */
	find := string([]byte{ch, '\''})

	found := strings.Index(s[pos+3:], find)
	if found == -1 {
		token := newToken(TYPE_STRING, pos+3, slen-pos-3, s[pos+3:])
		token.str_open = 'q'
		token.str_close = CHAR_NULL
		state.tokenvec[state.current] = token
		return slen
	} else {
		token := newToken(TYPE_STRING, pos+3, found-pos-3, s[pos+3:found])
		token.str_open = 'q'
		token.str_close = 'q'
		state.tokenvec[state.current] = token
		return found + 2 /* +2 to skip over )' or ]' or }' or >' */
	}

}

/*
 * Used when first char is N or n: mysql "National Character set"
 */
func (sqli *Sqli) parse_ustring() int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos

	if pos+2 < slen && s[pos+1] == '&' && s[pos+2] == '\'' {
		state.pos = state.pos + 2
		pos = sqli.parse_string()
		state.tokenvec[state.current].str_open = 'u'
		if state.tokenvec[state.current].str_close == '\'' {
			state.tokenvec[state.current].str_close = 'u'
		}
		return pos
	} else {
		return sqli.parse_word()
	}

}

/*
 * Used when first char is E : psql "Escaped String"
 */
func (sqli *Sqli) parse_estring() int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos

	if pos+2 >= slen || s[pos+1] != CHAR_SINGLE {
		return sqli.parse_word()
	}
	return sqli.parse_string_core(CHAR_SINGLE, 2)
}

/* Used when first char is ' or " */
func (sqli *Sqli) parse_string() int {
	state := sqli.state
	return sqli.parse_string_core(state.s[state.pos], 1)
}

/*
 * Look forward for doubling of delimiter
 *
 * case 'foo''bar' --> foo''bar
 *
 * ending quote isn't duplicated (i.e. escaped)
 * since it's the wrong char or EOL
 *
 */
func (sqli *Sqli) parse_string_core(delim byte, offset int) int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos
	qpos := strings.IndexByte(s[pos+offset:], delim) /* offset to skip first quote */
	/* real quote if offset > 0, simulated quote if not */
	str_open := byte(0x00)
	if offset > 0 {
		str_open = delim
	}

	for {
		if qpos == -1 {
			/* string ended with no trailing quote. add token */
			token := newToken(TYPE_STRING, pos+offset, slen-pos-offset, s[pos+offset:])
			token.str_open = str_open
			token.str_close = CHAR_NULL
			state.tokenvec[state.current] = token
			return slen
		} else if is_backslash_escaped(qpos-1, pos+offset, s) {
			qpos = strings.IndexByte(s[qpos+1:], delim)
			continue
		} else if is_double_delim_escaped(qpos, slen, s) {
			qpos = strings.IndexByte(s[qpos+2:], delim)
			continue
		} else {
			/* quote is closed: it's a normal string */
			token := newToken(TYPE_STRING, pos+offset, qpos-(pos+offset), s[pos+offset:qpos])
			token.str_open = str_open
			token.str_close = delim
			state.tokenvec[state.current] = token
			return qpos + 1
		}
	}
}

func (sqli *Sqli) parse_operator2() int {
	var ch byte
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos

	/* single operator at end of line */
	if pos+1 >= slen {
		return sqli.parse_operator1()
	}

	/* "<=>" */
	if pos+2 < slen && s[pos] == '<' && s[pos+1] == '=' && s[pos+2] == '>' {
		/*
		 * special 3-char operator
		 */
		token := newToken(TYPE_OPERATOR, pos, 3, "<=>")
		state.tokenvec[state.current] = token
		return pos + 3
	}

	/* 2-char operators: "-=", "+=", "!!", ":=", etc... */
	operator := s[pos : pos+2]
	ch = libinjection_sqli_lookup_word(operator)
	if ch != 0 {
		state.tokenvec[state.current] = newToken(int(ch), pos, 2, operator)
		return pos + 2
	}

	if s[pos] == ':' {
		/* ':' alone is not an operator */
		state.tokenvec[state.current] = newToken(TYPE_COLON, pos, 1, ":")
		return pos + 1
	} else {
		/* must be a 1-char operator */
		return sqli.parse_operator1()
	}
}

func (sqli *Sqli) parse_backslash() int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos

	/*
	 * Weird MySQL alias for NULL, "\N" (capital N only)
	 */
	if pos+1 < slen && s[pos+1] == 'N' {
		token := newToken(TYPE_NUMBER, pos, 2, s[pos:pos+2])
		state.tokenvec[state.current] = token
		return pos + 2
	} else {
		token := newToken(TYPE_BACKSLASH, pos, 1, string(s[pos]))
		state.tokenvec[state.current] = token
		return pos + 1
	}
}

func (sqli *Sqli) parse_slash() int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos

	/* not a comment */
	if pos+1 == slen || s[pos+1] != '*' {
		return sqli.parse_operator1()
	}

	/* is a comment */
	clen := 0
	ctype := TYPE_COMMENT
	cend := strings.Index(s[pos+2:], "*/") // index of * in */ (we do pos + 2 to skip over /*)
	closed := cend != -1

	if !closed {
		clen = slen - pos
		cend = slen - 2
	} else {
		clen = (cend + 2) - pos
	}

	/*
	 * postgresql allows nested comments which makes this is incompatible
	 * with parsing so if we find a '/x' inside the comment, then make a new
	 * token.
	 *
	 * Also, Mysql's "conditional" comments for version are an automatic
	 * black ban!
	 */
	if closed && strings.Contains(s[pos+2:cend+2], "/*") {
		ctype = TYPE_EVIL
	} else if is_mysql_comment(s, slen, pos) {
		ctype = TYPE_EVIL
	}

	token := newToken(int(ctype), pos, clen, s[pos:cend+2])
	state.tokenvec[state.current] = token
	return pos + clen
}

func (sqli *Sqli) parse_dash() int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos
	/*
	 * five cases:
	 * 1) --[white] this is always a SQL comment
	 * 2) --[EOF] this is a comment
	 * 3) --[notwhite] in MySQL this is NOT a comment but two unary operators
	 * 4) --[notwhite] everyone else thinks this is a comment
	 * 5) -[not dash] '-' is a unary operator
	 */
	if pos+2 < slen && s[pos+1] == '-' && char_is_white(s[pos+2]) {
		return sqli.parse_eol_comment()
	} else if pos+2 == slen && s[pos+1] == '-' {
		return sqli.parse_eol_comment()
	} else if pos+1 < slen && s[pos+1] == '-' && (state.flags&FLAG_SQL_ANSI) != 0 {
		state.stats_comment_ddx += 1
		return sqli.parse_eol_comment()
	} else {
		token := newToken(TYPE_OPERATOR, pos, 1, "-")
		state.tokenvec[state.current] = token
		return pos + 1
	}
}

/*
 * In ANSI mode, hash is an operator
 * In MYSQL mode, it's a EOL comment like '--'
 */
func (sqli *Sqli) parse_hash() int {
	state := sqli.state
	state.stats_comment_hash += 1
	if (state.flags & FLAG_SQL_MYSQL) != 0 {
		state.stats_comment_hash += 1
		return sqli.parse_eol_comment()
	} else {
		token := newToken(TYPE_OPERATOR, state.pos, 1, "#")
		state.tokenvec[state.current] = token
		return state.pos + 1
	}
}

func (sqli *Sqli) parse_eol_comment() int {
	state := sqli.state
	s := state.s
	slen := state.slen
	pos := state.pos

	/* first occurrence of '\n' starting from pos */
	endpos := strings.IndexByte(s[pos:], '\n')
	if endpos == -1 {
		token := newToken(TYPE_COMMENT, pos, slen-pos, s[pos:])
		state.tokenvec[state.current] = token
		return slen
	} else {
		/*
		 * tokenize from pos to endpos - 1.
		 * example: if "abc--\n" then tokenize "--"
		 */
		token := newToken(TYPE_COMMENT, pos, endpos-pos, s[pos:endpos])
		state.tokenvec[state.current] = token
		return endpos + 1
	}
}

func (sqli *Sqli) parse_char() int {
	state := sqli.state
	s := state.s
	pos := state.pos
	token := newToken(int(s[pos]), pos, 1, string(s[pos]))
	state.tokenvec[state.current] = token
	return pos + 1
}

func (sqli *Sqli) parse_other() int {
	state := sqli.state
	s := state.s
	pos := state.pos
	token := newToken(TYPE_UNKNOWN, pos, 1, string(s[pos]))
	state.tokenvec[state.current] = token
	return pos + 1
}

func (sqli *Sqli) parse_white() int {
	return sqli.state.pos + 1
}

func (sqli *Sqli) parse_operator1() int {
	state := sqli.state
	s := state.s
	pos := state.pos
	token := newToken(TYPE_OPERATOR, pos, 1, string(s[pos]))
	state.tokenvec[state.current] = token
	return pos + 1
}

/*
 * Tokenize, return whether there are more characters to tokenize
 */
func (sqli *Sqli) libinjection_sqli_tokenize() bool {
	state := sqli.state
	pos := state.pos
	slen := state.slen
	current := state.current
	s := state.s

	if slen == 0 {
		return false
	}

	/* clear token in current position (also to initialize) */
	state.tokenvec[current] = newToken(TYPE_NONE, 0, 0, "")

	/*
	 * if we are at beginning of string and in single-quote or double quote
	 * mode then pretend the input starts with a quote
	 */
	if pos == 0 && (state.flags&(FLAG_QUOTE_SINGLE|FLAG_QUOTE_DOUBLE)) != 0 {
		state.pos = sqli.parse_string_core(flag2delim(state.flags), 0)
		state.stats_tokens += 1
		return true
	}

	for pos < slen {
		ch := s[pos] /* current character */
		switch ch {
		case 0:
			pos = sqli.parse_white()
			break /* 0 */
		case 1:
			pos = sqli.parse_white()
			break /* 1 */
		case 2:
			pos = sqli.parse_white()
			break /* 2 */
		case 3:
			pos = sqli.parse_white()
			break /* 3 */
		case 4:
			pos = sqli.parse_white()
			break /* 4 */
		case 5:
			pos = sqli.parse_white()
			break /* 5 */
		case 6:
			pos = sqli.parse_white()
			break /* 6 */
		case 7:
			pos = sqli.parse_white()
			break /* 7 */
		case 8:
			pos = sqli.parse_white()
			break /* 8 */
		case 9:
			pos = sqli.parse_white()
			break /* 9 */
		case 10:
			pos = sqli.parse_white()
			break /* 10 */
		case 11:
			pos = sqli.parse_white()
			break /* 11 */
		case 12:
			pos = sqli.parse_white()
			break /* 12 */
		case 13:
			pos = sqli.parse_white()
			break /* 13 */
		case 14:
			pos = sqli.parse_white()
			break /* 14 */
		case 15:
			pos = sqli.parse_white()
			break /* 15 */
		case 16:
			pos = sqli.parse_white()
			break /* 16 */
		case 17:
			pos = sqli.parse_white()
			break /* 17 */
		case 18:
			pos = sqli.parse_white()
			break /* 18 */
		case 19:
			pos = sqli.parse_white()
			break /* 19 */
		case 20:
			pos = sqli.parse_white()
			break /* 20 */
		case 21:
			pos = sqli.parse_white()
			break /* 21 */
		case 22:
			pos = sqli.parse_white()
			break /* 22 */
		case 23:
			pos = sqli.parse_white()
			break /* 23 */
		case 24:
			pos = sqli.parse_white()
			break /* 24 */
		case 25:
			pos = sqli.parse_white()
			break /* 25 */
		case 26:
			pos = sqli.parse_white()
			break /* 26 */
		case 27:
			pos = sqli.parse_white()
			break /* 27 */
		case 28:
			pos = sqli.parse_white()
			break /* 28 */
		case 29:
			pos = sqli.parse_white()
			break /* 29 */
		case 30:
			pos = sqli.parse_white()
			break /* 30 */
		case 31:
			pos = sqli.parse_white()
			break /* 31 */
		case 32:
			pos = sqli.parse_white()
			break /* 32 */
		case 33:
			pos = sqli.parse_operator2()
			break /* 33 */
		case 34:
			pos = sqli.parse_string()
			break /* 34 */
		case 35:
			pos = sqli.parse_hash()
			break /* 35 */
		case 36:
			pos = sqli.parse_money()
			break /* 36 */
		case 37:
			pos = sqli.parse_operator1()
			break /* 37 */
		case 38:
			pos = sqli.parse_operator2()
			break /* 38 */
		case 39:
			pos = sqli.parse_string()
			break /* 39 */
		case 40:
			pos = sqli.parse_char()
			break /* 40 */
		case 41:
			pos = sqli.parse_char()
			break /* 41 */
		case 42:
			pos = sqli.parse_operator2()
			break /* 42 */
		case 43:
			pos = sqli.parse_operator1()
			break /* 43 */
		case 44:
			pos = sqli.parse_char()
			break /* 44 */
		case 45:
			pos = sqli.parse_dash()
			break /* 45 */
		case 46:
			pos = sqli.parse_number()
			break /* 46 */
		case 47:
			pos = sqli.parse_slash()
			break /* 47 */
		case 48:
			pos = sqli.parse_number()
			break /* 48 */
		case 49:
			pos = sqli.parse_number()
			break /* 49 */
		case 50:
			pos = sqli.parse_number()
			break /* 50 */
		case 51:
			pos = sqli.parse_number()
			break /* 51 */
		case 52:
			pos = sqli.parse_number()
			break /* 52 */
		case 53:
			pos = sqli.parse_number()
			break /* 53 */
		case 54:
			pos = sqli.parse_number()
			break /* 54 */
		case 55:
			pos = sqli.parse_number()
			break /* 55 */
		case 56:
			pos = sqli.parse_number()
			break /* 56 */
		case 57:
			pos = sqli.parse_number()
			break /* 57 */
		case 58:
			pos = sqli.parse_operator2()
			break /* 58 */
		case 59:
			pos = sqli.parse_char()
			break /* 59 */
		case 60:
			pos = sqli.parse_operator2()
			break /* 60 */
		case 61:
			pos = sqli.parse_operator2()
			break /* 61 */
		case 62:
			pos = sqli.parse_operator2()
			break /* 62 */
		case 63:
			pos = sqli.parse_other()
			break /* 63 */
		case 64:
			pos = sqli.parse_var()
			break /* 64 */
		case 65:
			pos = sqli.parse_word()
			break /* 65 */
		case 66:
			pos = sqli.parse_bstring()
			break /* 66 */
		case 67:
			pos = sqli.parse_word()
			break /* 67 */
		case 68:
			pos = sqli.parse_word()
			break /* 68 */
		case 69:
			pos = sqli.parse_estring()
			break /* 69 */
		case 70:
			pos = sqli.parse_word()
			break /* 70 */
		case 71:
			pos = sqli.parse_word()
			break /* 71 */
		case 72:
			pos = sqli.parse_word()
			break /* 72 */
		case 73:
			pos = sqli.parse_word()
			break /* 73 */
		case 74:
			pos = sqli.parse_word()
			break /* 74 */
		case 75:
			pos = sqli.parse_word()
			break /* 75 */
		case 76:
			pos = sqli.parse_word()
			break /* 76 */
		case 77:
			pos = sqli.parse_word()
			break /* 77 */
		case 78:
			pos = sqli.parse_nqstring()
			break /* 78 */
		case 79:
			pos = sqli.parse_word()
			break /* 79 */
		case 80:
			pos = sqli.parse_word()
			break /* 80 */
		case 81:
			pos = sqli.parse_qstring()
			break /* 81 */
		case 82:
			pos = sqli.parse_word()
			break /* 82 */
		case 83:
			pos = sqli.parse_word()
			break /* 83 */
		case 84:
			pos = sqli.parse_word()
			break /* 84 */
		case 85:
			pos = sqli.parse_ustring()
			break /* 85 */
		case 86:
			pos = sqli.parse_word()
			break /* 86 */
		case 87:
			pos = sqli.parse_word()
			break /* 87 */
		case 88:
			pos = sqli.parse_xstring()
			break /* 88 */
		case 89:
			pos = sqli.parse_word()
			break /* 89 */
		case 90:
			pos = sqli.parse_word()
			break /* 90 */
		case 91:
			pos = sqli.parse_bword()
			break /* 91 */
		case 92:
			pos = sqli.parse_backslash()
			break /* 92 */
		case 93:
			pos = sqli.parse_other()
			break /* 93 */
		case 94:
			pos = sqli.parse_operator1()
			break /* 94 */
		case 95:
			pos = sqli.parse_word()
			break /* 95 */
		case 96:
			pos = sqli.parse_tick()
			break /* 96 */
		case 97:
			pos = sqli.parse_word()
			break /* 97 */
		case 98:
			pos = sqli.parse_bstring()
			break /* 98 */
		case 99:
			pos = sqli.parse_word()
			break /* 99 */
		case 100:
			pos = sqli.parse_word()
			break /* 100 */
		case 101:
			pos = sqli.parse_estring()
			break /* 101 */
		case 102:
			pos = sqli.parse_word()
			break /* 102 */
		case 103:
			pos = sqli.parse_word()
			break /* 103 */
		case 104:
			pos = sqli.parse_word()
			break /* 104 */
		case 105:
			pos = sqli.parse_word()
			break /* 105 */
		case 106:
			pos = sqli.parse_word()
			break /* 106 */
		case 107:
			pos = sqli.parse_word()
			break /* 107 */
		case 108:
			pos = sqli.parse_word()
			break /* 108 */
		case 109:
			pos = sqli.parse_word()
			break /* 109 */
		case 110:
			pos = sqli.parse_nqstring()
			break /* 110 */
		case 111:
			pos = sqli.parse_word()
			break /* 111 */
		case 112:
			pos = sqli.parse_word()
			break /* 112 */
		case 113:
			pos = sqli.parse_qstring()
			break /* 113 */
		case 114:
			pos = sqli.parse_word()
			break /* 114 */
		case 115:
			pos = sqli.parse_word()
			break /* 115 */
		case 116:
			pos = sqli.parse_word()
			break /* 116 */
		case 117:
			pos = sqli.parse_ustring()
			break /* 117 */
		case 118:
			pos = sqli.parse_word()
			break /* 118 */
		case 119:
			pos = sqli.parse_word()
			break /* 119 */
		case 120:
			pos = sqli.parse_xstring()
			break /* 120 */
		case 121:
			pos = sqli.parse_word()
			break /* 121 */
		case 122:
			pos = sqli.parse_word()
			break /* 122 */
		case 123:
			pos = sqli.parse_char()
			break /* 123 */
		case 124:
			pos = sqli.parse_operator2()
			break /* 124 */
		case 125:
			pos = sqli.parse_char()
			break /* 125 */
		case 126:
			pos = sqli.parse_operator1()
			break /* 126 */
		case 127:
			pos = sqli.parse_white()
			break /* 127 */
		case 128:
			pos = sqli.parse_word()
			break /* 128 */
		case 129:
			pos = sqli.parse_word()
			break /* 129 */
		case 130:
			pos = sqli.parse_word()
			break /* 130 */
		case 131:
			pos = sqli.parse_word()
			break /* 131 */
		case 132:
			pos = sqli.parse_word()
			break /* 132 */
		case 133:
			pos = sqli.parse_word()
			break /* 133 */
		case 134:
			pos = sqli.parse_word()
			break /* 134 */
		case 135:
			pos = sqli.parse_word()
			break /* 135 */
		case 136:
			pos = sqli.parse_word()
			break /* 136 */
		case 137:
			pos = sqli.parse_word()
			break /* 137 */
		case 138:
			pos = sqli.parse_word()
			break /* 138 */
		case 139:
			pos = sqli.parse_word()
			break /* 139 */
		case 140:
			pos = sqli.parse_word()
			break /* 140 */
		case 141:
			pos = sqli.parse_word()
			break /* 141 */
		case 142:
			pos = sqli.parse_word()
			break /* 142 */
		case 143:
			pos = sqli.parse_word()
			break /* 143 */
		case 144:
			pos = sqli.parse_word()
			break /* 144 */
		case 145:
			pos = sqli.parse_word()
			break /* 145 */
		case 146:
			pos = sqli.parse_word()
			break /* 146 */
		case 147:
			pos = sqli.parse_word()
			break /* 147 */
		case 148:
			pos = sqli.parse_word()
			break /* 148 */
		case 149:
			pos = sqli.parse_word()
			break /* 149 */
		case 150:
			pos = sqli.parse_word()
			break /* 150 */
		case 151:
			pos = sqli.parse_word()
			break /* 151 */
		case 152:
			pos = sqli.parse_word()
			break /* 152 */
		case 153:
			pos = sqli.parse_word()
			break /* 153 */
		case 154:
			pos = sqli.parse_word()
			break /* 154 */
		case 155:
			pos = sqli.parse_word()
			break /* 155 */
		case 156:
			pos = sqli.parse_word()
			break /* 156 */
		case 157:
			pos = sqli.parse_word()
			break /* 157 */
		case 158:
			pos = sqli.parse_word()
			break /* 158 */
		case 159:
			pos = sqli.parse_word()
			break /* 159 */
		case 160:
			pos = sqli.parse_white()
			break /* 160 */
		case 161:
			pos = sqli.parse_word()
			break /* 161 */
		case 162:
			pos = sqli.parse_word()
			break /* 162 */
		case 163:
			pos = sqli.parse_word()
			break /* 163 */
		case 164:
			pos = sqli.parse_word()
			break /* 164 */
		case 165:
			pos = sqli.parse_word()
			break /* 165 */
		case 166:
			pos = sqli.parse_word()
			break /* 166 */
		case 167:
			pos = sqli.parse_word()
			break /* 167 */
		case 168:
			pos = sqli.parse_word()
			break /* 168 */
		case 169:
			pos = sqli.parse_word()
			break /* 169 */
		case 170:
			pos = sqli.parse_word()
			break /* 170 */
		case 171:
			pos = sqli.parse_word()
			break /* 171 */
		case 172:
			pos = sqli.parse_word()
			break /* 172 */
		case 173:
			pos = sqli.parse_word()
			break /* 173 */
		case 174:
			pos = sqli.parse_word()
			break /* 174 */
		case 175:
			pos = sqli.parse_word()
			break /* 175 */
		case 176:
			pos = sqli.parse_word()
			break /* 176 */
		case 177:
			pos = sqli.parse_word()
			break /* 177 */
		case 178:
			pos = sqli.parse_word()
			break /* 178 */
		case 179:
			pos = sqli.parse_word()
			break /* 179 */
		case 180:
			pos = sqli.parse_word()
			break /* 180 */
		case 181:
			pos = sqli.parse_word()
			break /* 181 */
		case 182:
			pos = sqli.parse_word()
			break /* 182 */
		case 183:
			pos = sqli.parse_word()
			break /* 183 */
		case 184:
			pos = sqli.parse_word()
			break /* 184 */
		case 185:
			pos = sqli.parse_word()
			break /* 185 */
		case 186:
			pos = sqli.parse_word()
			break /* 186 */
		case 187:
			pos = sqli.parse_word()
			break /* 187 */
		case 188:
			pos = sqli.parse_word()
			break /* 188 */
		case 189:
			pos = sqli.parse_word()
			break /* 189 */
		case 190:
			pos = sqli.parse_word()
			break /* 190 */
		case 191:
			pos = sqli.parse_word()
			break /* 191 */
		case 192:
			pos = sqli.parse_word()
			break /* 192 */
		case 193:
			pos = sqli.parse_word()
			break /* 193 */
		case 194:
			pos = sqli.parse_word()
			break /* 194 */
		case 195:
			pos = sqli.parse_word()
			break /* 195 */
		case 196:
			pos = sqli.parse_word()
			break /* 196 */
		case 197:
			pos = sqli.parse_word()
			break /* 197 */
		case 198:
			pos = sqli.parse_word()
			break /* 198 */
		case 199:
			pos = sqli.parse_word()
			break /* 199 */
		case 200:
			pos = sqli.parse_word()
			break /* 200 */
		case 201:
			pos = sqli.parse_word()
			break /* 201 */
		case 202:
			pos = sqli.parse_word()
			break /* 202 */
		case 203:
			pos = sqli.parse_word()
			break /* 203 */
		case 204:
			pos = sqli.parse_word()
			break /* 204 */
		case 205:
			pos = sqli.parse_word()
			break /* 205 */
		case 206:
			pos = sqli.parse_word()
			break /* 206 */
		case 207:
			pos = sqli.parse_word()
			break /* 207 */
		case 208:
			pos = sqli.parse_word()
			break /* 208 */
		case 209:
			pos = sqli.parse_word()
			break /* 209 */
		case 210:
			pos = sqli.parse_word()
			break /* 210 */
		case 211:
			pos = sqli.parse_word()
			break /* 211 */
		case 212:
			pos = sqli.parse_word()
			break /* 212 */
		case 213:
			pos = sqli.parse_word()
			break /* 213 */
		case 214:
			pos = sqli.parse_word()
			break /* 214 */
		case 215:
			pos = sqli.parse_word()
			break /* 215 */
		case 216:
			pos = sqli.parse_word()
			break /* 216 */
		case 217:
			pos = sqli.parse_word()
			break /* 217 */
		case 218:
			pos = sqli.parse_word()
			break /* 218 */
		case 219:
			pos = sqli.parse_word()
			break /* 219 */
		case 220:
			pos = sqli.parse_word()
			break /* 220 */
		case 221:
			pos = sqli.parse_word()
			break /* 221 */
		case 222:
			pos = sqli.parse_word()
			break /* 222 */
		case 223:
			pos = sqli.parse_word()
			break /* 223 */
		case 224:
			pos = sqli.parse_word()
			break /* 224 */
		case 225:
			pos = sqli.parse_word()
			break /* 225 */
		case 226:
			pos = sqli.parse_word()
			break /* 226 */
		case 227:
			pos = sqli.parse_word()
			break /* 227 */
		case 228:
			pos = sqli.parse_word()
			break /* 228 */
		case 229:
			pos = sqli.parse_word()
			break /* 229 */
		case 230:
			pos = sqli.parse_word()
			break /* 230 */
		case 231:
			pos = sqli.parse_word()
			break /* 231 */
		case 232:
			pos = sqli.parse_word()
			break /* 232 */
		case 233:
			pos = sqli.parse_word()
			break /* 233 */
		case 234:
			pos = sqli.parse_word()
			break /* 234 */
		case 235:
			pos = sqli.parse_word()
			break /* 235 */
		case 236:
			pos = sqli.parse_word()
			break /* 236 */
		case 237:
			pos = sqli.parse_word()
			break /* 237 */
		case 238:
			pos = sqli.parse_word()
			break /* 238 */
		case 239:
			pos = sqli.parse_word()
			break /* 239 */
		case 240:
			pos = sqli.parse_word()
			break /* 240 */
		case 241:
			pos = sqli.parse_word()
			break /* 241 */
		case 242:
			pos = sqli.parse_word()
			break /* 242 */
		case 243:
			pos = sqli.parse_word()
			break /* 243 */
		case 244:
			pos = sqli.parse_word()
			break /* 244 */
		case 245:
			pos = sqli.parse_word()
			break /* 245 */
		case 246:
			pos = sqli.parse_word()
			break /* 246 */
		case 247:
			pos = sqli.parse_word()
			break /* 247 */
		case 248:
			pos = sqli.parse_word()
			break /* 248 */
		case 249:
			pos = sqli.parse_word()
			break /* 249 */
		case 250:
			pos = sqli.parse_word()
			break /* 250 */
		case 251:
			pos = sqli.parse_word()
			break /* 251 */
		case 252:
			pos = sqli.parse_word()
			break /* 252 */
		case 253:
			pos = sqli.parse_word()
			break /* 253 */
		case 254:
			pos = sqli.parse_word()
			break /* 254 */
		case 255:
			pos = sqli.parse_word()
			break /* 255 */
		default: /* move on if not in standard ascii set */
			pos = pos + 1
			break
		}
		state.pos = pos
		if state.tokenvec[current].Type != CHAR_NULL {
			state.stats_tokens += 1
			return true
		}
	}
	return false
}

func (sqli *Sqli) libinjection_sqli_fold() (int, error) {
	state := sqli.state
	pos := 0     /* position where NEXT token goes */
	left := 0    /* # of tokens so far that will be part of the final fingerprint */
	more := true /* more characters in input to check? */
	current := state.current
	last_comment := newToken(CHAR_NULL, 0, 0, "") /* A comment token to add additional info */

	/* skip stuff we don't need to look at */
	for more {
		more = sqli.libinjection_sqli_tokenize()
		if !(state.tokenvec[current].Type == TYPE_COMMENT || state.tokenvec[current].Type == TYPE_LEFTPARENS || state.tokenvec[current].Type == TYPE_SQLTYPE || state.tokenvec[current].is_unary_op()) {
			break
		}
	}

	if !more {
		return 0, nil
	} else {
		pos += 1
	}

	/* the actual tokenizing and folding */
	for {
		/*
		 * do we have all the max number of tokens? if so do some special
		 * cases for 5 tokens
		 */
		if pos >= LIBINJECTION_SQLI_MAX_TOKENS {
			if (state.tokenvec[0].Type == TYPE_NUMBER &&
				(state.tokenvec[1].Type == TYPE_OPERATOR || state.tokenvec[1].Type == TYPE_COMMA) &&
				state.tokenvec[2].Type == TYPE_LEFTPARENS &&
				state.tokenvec[3].Type == TYPE_NUMBER &&
				state.tokenvec[4].Type == TYPE_RIGHTPARENS) ||
				(state.tokenvec[0].Type == TYPE_BAREWORD &&
					state.tokenvec[1].Type == TYPE_OPERATOR &&
					state.tokenvec[2].Type == TYPE_LEFTPARENS &&
					(state.tokenvec[3].Type == TYPE_BAREWORD || state.tokenvec[3].Type == TYPE_NUMBER) &&
					state.tokenvec[4].Type == TYPE_RIGHTPARENS) ||
				(state.tokenvec[0].Type == TYPE_NUMBER &&
					state.tokenvec[1].Type == TYPE_RIGHTPARENS &&
					state.tokenvec[2].Type == TYPE_COMMA &&
					state.tokenvec[3].Type == TYPE_LEFTPARENS &&
					state.tokenvec[4].Type == TYPE_NUMBER) ||
				(state.tokenvec[0].Type == TYPE_BAREWORD &&
					state.tokenvec[1].Type == TYPE_RIGHTPARENS &&
					state.tokenvec[2].Type == TYPE_OPERATOR &&
					state.tokenvec[3].Type == TYPE_LEFTPARENS &&
					state.tokenvec[4].Type == TYPE_BAREWORD) {
				if pos > LIBINJECTION_SQLI_MAX_TOKENS {
					state.tokenvec[1] = state.tokenvec[LIBINJECTION_SQLI_MAX_TOKENS]
					pos = 2
					left = 0
				} else {
					pos = 1
					left = 0
				}
			}
		}

		/* if checked all of input or # of tokens in fingerprint exceeds 5, stop. */
		if !more || left >= LIBINJECTION_SQLI_MAX_TOKENS {
			left = pos
			break
		}

		/* get up to two tokens */
		for more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos-left) < 2 {
			state.current = pos
			current = state.current

			more = sqli.libinjection_sqli_tokenize()
			if more {
				if state.tokenvec[current].Type == TYPE_COMMENT {
					last_comment = state.tokenvec[current]
				} else {
					last_comment.Type = CHAR_NULL
					pos += 1
				}
			}
		}

		/*
		 * if we didn't get at least two tokens, it means we exited above
		 * while loop because we:
		 * 1.) processed all of the input OR
		 * 2.) added the 5th (and last) token
		 * In this case start over
		 */
		if pos-left < 2 {
			left = pos
			continue
		}

		/*
		 * two token folding
		 */
		if state.tokenvec[left].Type == TYPE_STRING && state.tokenvec[left+1].Type == TYPE_STRING {
			pos -= 1
			state.stats_folds += 1
			continue
		} else if state.tokenvec[left].Type == TYPE_SEMICOLON && state.tokenvec[left+1].Type == TYPE_SEMICOLON {
			/* fold away repeated semicolons. i.e. ;; to ; */
			pos -= 1
			state.stats_folds += 1
			continue
		} else if state.tokenvec[left].Type == TYPE_SEMICOLON &&
			state.tokenvec[left+1].Type == TYPE_FUNCTION &&
			strings.EqualFold(state.tokenvec[left+1].val, "IF") {
			state.tokenvec[left+1].Type = TYPE_TSQL
			left += 2
			continue /*reparse everything. but we probably can advance left, and pos */
		} else if (state.tokenvec[left].Type == TYPE_OPERATOR || state.tokenvec[left].Type == TYPE_LOGIC_OPERATOR) &&
			(state.tokenvec[left+1].is_unary_op() || state.tokenvec[left+1].Type == TYPE_SQLTYPE) {
			pos -= 1
			state.stats_folds += 1
			left = 0
			continue
		} else if state.tokenvec[left].Type == TYPE_LEFTPARENS && state.tokenvec[left+1].is_unary_op() {
			pos -= 1
			state.stats_folds += 1
			if left > 0 {
				left -= 1
			}
			continue
		} else if state.tokenvec[left].syntax_merge_words(sqli, left, state.tokenvec[left+1], left+1) {
			pos -= 1
			state.stats_folds += 1
			if left > 0 {
				left -= 1
			}
			continue
			/* ELSE two token handling. */
		} else if (state.tokenvec[left].Type == TYPE_BAREWORD || state.tokenvec[left].Type == TYPE_VARIABLE) &&
			state.tokenvec[left+1].Type == TYPE_LEFTPARENS &&
			/* TSQL functions but common enough to be column names */
			(strings.EqualFold(state.tokenvec[left].val, "USER_ID") || strings.EqualFold(state.tokenvec[left].val, "USER_NAME") ||

				/* Function in MYSQL */
				strings.EqualFold(state.tokenvec[left].val, "DATABASE") ||
				strings.EqualFold(state.tokenvec[left].val, "PASSWORD") ||
				strings.EqualFold(state.tokenvec[left].val, "USER") ||

				/*
				 * Mysql words that act as a variable and are a
				 * function
				 */

				/* TSQL current_users is fake-variable */
				/*
				 * http://msdn.microsoft.com/en-us/library/ms176050.
				 * aspx
				 */
				strings.EqualFold(state.tokenvec[left].val, "CURRENT_USER") ||
				strings.EqualFold(state.tokenvec[left].val, "CURRENT_DATE") ||
				strings.EqualFold(state.tokenvec[left].val, "CURRENT_TIME") ||
				strings.EqualFold(state.tokenvec[left].val, "CURRENT_TIMESTAMP") ||
				strings.EqualFold(state.tokenvec[left].val, "LOCALTIME") ||
				strings.EqualFold(state.tokenvec[left].val, "LOCALTIMESTAMP")) {
			/*
			 * pos is the same other conversions need to go here... for
			 * instance password CAN be a function, coalesce CAN be a
			 * function
			 */
			state.tokenvec[left].Type = TYPE_FUNCTION
			continue
		} else if state.tokenvec[left].Type == TYPE_KEYWORD &&
			(strings.EqualFold(state.tokenvec[left].val, "IN") ||
				strings.EqualFold(state.tokenvec[left].val, "NOT IN")) {

			if state.tokenvec[left+1].Type == TYPE_LEFTPARENS {
				/* got .... IN ( ... (or 'NOT IN') it's an operator */
				state.tokenvec[left].Type = TYPE_OPERATOR
			} else {
				/* it's a nothing */
				state.tokenvec[left].Type = TYPE_BAREWORD
			}

			/*
			 * "IN" can be used as "IN BOOLEAN MODE" for mysql in which case
			 * merging of words can be done later other wise it acts as an
			 * equality operator __ IN (values..)
			 *
			 * here we got "IN" "(" so it's an operator. also back track to
			 * handle "NOT IN" might need to do the same with like two use
			 * cases "foo" LIKE "BAR" (normal operator) "foo" = LIKE(1,2)
			 */
			continue
		} else if (state.tokenvec[left].Type == TYPE_OPERATOR) &&
			(strings.EqualFold(state.tokenvec[left].val, "LIKE") ||
				strings.EqualFold(state.tokenvec[left].val, "NOT LIKE")) {
			if state.tokenvec[left+1].Type == TYPE_LEFTPARENS {
				/* SELECT LIKE(... it's a function */
				state.tokenvec[left].Type = TYPE_FUNCTION
			}
		} else if state.tokenvec[left].Type == TYPE_SQLTYPE && (state.tokenvec[left+1].Type == TYPE_BAREWORD ||
			state.tokenvec[left+1].Type == TYPE_NUMBER ||
			state.tokenvec[left+1].Type == TYPE_SQLTYPE ||
			state.tokenvec[left+1].Type == TYPE_LEFTPARENS ||
			state.tokenvec[left+1].Type == TYPE_FUNCTION ||
			state.tokenvec[left+1].Type == TYPE_VARIABLE ||
			state.tokenvec[left+1].Type == TYPE_STRING) {
			state.tokenvec[left] = state.tokenvec[left+1]
			pos -= 1
			state.stats_folds += 1
			left = 0
			continue
		} else if state.tokenvec[left].Type == TYPE_COLLATE && state.tokenvec[left+1].Type == TYPE_BAREWORD {
			/*
			 * there are too many collation types.. so if the bareword has a
			 * "_" then it's TYPE_SQLTYPE
			 */
			if strings.IndexByte(state.tokenvec[left+1].val, '_') != -1 {
				state.tokenvec[left+1].Type = TYPE_SQLTYPE
				left = 0
			}
		} else if state.tokenvec[left].Type == TYPE_BACKSLASH {
			if state.tokenvec[left+1].is_arithmetic_op() {
				/* very weird case in TSQL where '\%1' is parsed as '0 % 1',etc */
				state.tokenvec[left].Type = TYPE_NUMBER
			} else {
				/* just ignore it.. Again T-SQL seems to parse \1 as "1" */
				state.tokenvec[left] = state.tokenvec[left+1]
				pos -= 1
				state.stats_folds += 1
			}
			left = 0
			continue
		} else if state.tokenvec[left].Type == TYPE_LEFTPARENS && state.tokenvec[left+1].Type == TYPE_LEFTPARENS {
			pos -= 1
			left = 0
			state.stats_folds += 1
			continue
		} else if state.tokenvec[left].Type == TYPE_RIGHTPARENS && state.tokenvec[left+1].Type == TYPE_RIGHTPARENS {
			pos -= 1
			left = 0
			state.stats_folds += 1
			continue
		} else if state.tokenvec[left].Type == TYPE_LEFTBRACE && state.tokenvec[left+1].Type == TYPE_BAREWORD {

			/*
			 * MySQL Degenerate case --
			 *
			 * select { ``.``.id }; -- valid !!! select { ``.``.``.id }; --
			 * invalid select ``.``.id; -- invalid select { ``.id }; --
			 * invalid
			 *
			 * so it appears {``.``.id} is a magic case I suspect this is
			 * "current database, current table, field id"
			 *
			 * The folding code can't look at more than 3 tokens, and I
			 * don't want to make two passes.
			 *
			 * Since "{ ``" so rare, we are just going to blacklist it.
			 *
			 * Highly likely this will need revisiting!
			 *
			 * CREDIT @rsalgado 2013-11-25
			 */
			if state.tokenvec[left+1].Len == 0 {
				state.tokenvec[left+1].Type = TYPE_EVIL
				return (int)(left + 2), nil
			}
			/*
			 * weird ODBC / MYSQL {foo expr} --> expr but for this rule we
			 * just strip away the "{ foo" part
			 */
			left = 0
			pos -= 2
			state.stats_folds += 2
			continue
		} else if state.tokenvec[left+1].Type == TYPE_RIGHTBRACE {
			pos -= 1
			left = 0
			state.stats_folds += 1
			continue
		}

		/*
		 * all cases of handling 2 tokens is done and nothing matched. Get
		 * one more token
		 */
		for more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos-left) < 3 {
			state.current = pos
			current = state.current

			more = sqli.libinjection_sqli_tokenize()
			if more {
				if state.tokenvec[current].Type == TYPE_COMMENT {
					last_comment = state.tokenvec[current]
				} else {
					last_comment.Type = CHAR_NULL
					pos += 1
				}
			}
		}

		/*
		 * if we didn't get at least three tokens, it means we exited above
		 * while loop because we:
		 * 1.) processed all of the input OR
		 * 2.) added the 5th (and last) token
		 * In this case start over.
		 */
		if pos-left < 3 {
			left = pos
			continue
		}

		/*
		 * Three token folding
		 */

		if state.tokenvec[left].Type == TYPE_NUMBER &&
			state.tokenvec[left+1].Type == TYPE_OPERATOR &&
			state.tokenvec[left+2].Type == TYPE_NUMBER {
			pos -= 2
			left = 0
			continue
		} else if state.tokenvec[left].Type == TYPE_OPERATOR &&
			state.tokenvec[left+1].Type != TYPE_LEFTPARENS &&
			state.tokenvec[left+2].Type == TYPE_OPERATOR {
			left = 0
			pos -= 2
			continue
		} else if state.tokenvec[left].Type == TYPE_LOGIC_OPERATOR &&
			state.tokenvec[left+2].Type == TYPE_LOGIC_OPERATOR {
			pos -= 2
			left = 0
			continue
		} else if state.tokenvec[left].Type == TYPE_VARIABLE &&
			state.tokenvec[left+1].Type == TYPE_OPERATOR &&
			(state.tokenvec[left+2].Type == TYPE_VARIABLE ||
				state.tokenvec[left+2].Type == TYPE_NUMBER ||
				state.tokenvec[left+2].Type == TYPE_BAREWORD) {
			pos -= 2
			left = 0
			continue
		} else if (state.tokenvec[left].Type == TYPE_BAREWORD || state.tokenvec[left].Type == TYPE_NUMBER) &&
			state.tokenvec[left+1].Type == TYPE_OPERATOR &&
			(state.tokenvec[left+2].Type == TYPE_NUMBER || state.tokenvec[left+2].Type == TYPE_BAREWORD) {
			pos -= 2
			left = 0
			continue
		} else if (state.tokenvec[left].Type == TYPE_BAREWORD ||
			state.tokenvec[left].Type == TYPE_NUMBER ||
			state.tokenvec[left].Type == TYPE_VARIABLE ||
			state.tokenvec[left].Type == TYPE_STRING) &&
			state.tokenvec[left+1].Type == TYPE_OPERATOR &&
			state.tokenvec[left+1].val == "::" &&
			state.tokenvec[left+2].Type == TYPE_SQLTYPE {
			pos -= 2
			left = 0
			state.stats_folds += 2
			continue
		} else if (state.tokenvec[left].Type == TYPE_BAREWORD ||
			state.tokenvec[left].Type == TYPE_NUMBER ||
			state.tokenvec[left].Type == TYPE_STRING ||
			state.tokenvec[left].Type == TYPE_VARIABLE) &&
			state.tokenvec[left+1].Type == TYPE_COMMA &&
			(state.tokenvec[left+2].Type == TYPE_NUMBER ||
				state.tokenvec[left+2].Type == TYPE_BAREWORD ||
				state.tokenvec[left+2].Type == TYPE_STRING ||
				state.tokenvec[left+2].Type == TYPE_VARIABLE) {
			pos -= 2
			left = 0
			continue
		} else if (state.tokenvec[left].Type == TYPE_EXPRESSION ||
			state.tokenvec[left].Type == TYPE_GROUP ||
			state.tokenvec[left].Type == TYPE_COMMA) &&
			state.tokenvec[left+1].is_unary_op() &&
			state.tokenvec[left+2].Type == TYPE_LEFTPARENS {
			/*
			 * got something like SELECT + (, LIMIT + ( remove unary
			 * operator
			 */
			state.tokenvec[left+1] = state.tokenvec[left+2]
			pos -= 1
			left = 0
			continue
		} else if (state.tokenvec[left].Type == TYPE_KEYWORD ||
			state.tokenvec[left].Type == TYPE_EXPRESSION ||
			state.tokenvec[left].Type == TYPE_GROUP) &&
			state.tokenvec[left+1].is_unary_op() &&
			(state.tokenvec[left+2].Type == TYPE_NUMBER ||
				state.tokenvec[left+2].Type == TYPE_BAREWORD ||
				state.tokenvec[left+2].Type == TYPE_VARIABLE ||
				state.tokenvec[left+2].Type == TYPE_STRING ||
				state.tokenvec[left+2].Type == TYPE_FUNCTION) {
			/*
			 * remove unary operators select - 1
			 */
			state.tokenvec[left+1] = state.tokenvec[left+2]
			pos -= 1
			left = 0
			continue
		} else if state.tokenvec[left].Type == TYPE_COMMA && state.tokenvec[left+1].is_unary_op() &&
			(state.tokenvec[left+2].Type == TYPE_NUMBER ||
				state.tokenvec[left+2].Type == TYPE_BAREWORD ||
				state.tokenvec[left+2].Type == TYPE_VARIABLE ||
				state.tokenvec[left+2].Type == TYPE_STRING) {
			/*
			 * interesting case turn ", -1" ->> ",1" PLUS we need to back up
			 * one token if possible to see if more folding can be done
			 * "1,-1" --> "1"
			 */
			state.tokenvec[left+1] = state.tokenvec[left+2]
			left = 0
			/* pos is >= 3 so this is safe */
			if pos < 3 {
				//assert(pos >= 3)
				return 0, fmt.Errorf("failed assertion")
			}
			pos -= 3
			continue
		} else if state.tokenvec[left].Type == TYPE_COMMA &&
			state.tokenvec[left+1].is_unary_op() &&
			state.tokenvec[left+2].Type == TYPE_FUNCTION {

			/*
			 * Separate case from above since you end up with 1,-sin(1) -->
			 * 1 (1) Here, just do 1,-sin(1) --> 1,sin(1) just remove unary
			 * operator
			 */
			state.tokenvec[left+1] = state.tokenvec[left+2]
			pos -= 1
			left = 0
			continue
		} else if (state.tokenvec[left].Type == TYPE_BAREWORD) &&
			(state.tokenvec[left+1].Type == TYPE_DOT) &&
			(state.tokenvec[left+2].Type == TYPE_BAREWORD) {
			/*
			 * ignore the '.n' typically is this databasename.table
			 */
			if pos < 3 {
				//assert(pos >= 3)
				return 0, fmt.Errorf("failed assertion")
			}
			pos -= 2
			left = 0
			continue
		} else if (state.tokenvec[left].Type == TYPE_EXPRESSION) &&
			(state.tokenvec[left+1].Type == TYPE_DOT) &&
			(state.tokenvec[left+2].Type == TYPE_BAREWORD) {
			/*
			 * select . `foo` --> select `foo`
			 */
			state.tokenvec[left+1] = state.tokenvec[left+2]
			pos -= 1
			left = 0
			continue
		} else if (state.tokenvec[left].Type == TYPE_FUNCTION) &&
			(state.tokenvec[left+1].Type == TYPE_LEFTPARENS) &&
			(state.tokenvec[left+2].Type != TYPE_RIGHTPARENS) {
			/*
			 * whats going on here Some SQL functions like USER() have 0
			 * args if we get User(foo), then User is not a function This
			 * should be expanded since it eliminated a lot of false
			 * positives.
			 */
			if strings.EqualFold(state.tokenvec[left].val, "USER") {
				state.tokenvec[left].Type = TYPE_BAREWORD
			}
		}

		/*
		 * assume left-most token is good, now use the existing 2 tokens,
		 * do not get another
		 */
		left += 1

	} /* while(1) */

	/*
	 * if we have 4 or less tokens, and we had a comment token at the end,
	 * add it back
	 */
	if left < LIBINJECTION_SQLI_MAX_TOKENS && last_comment.Type == TYPE_COMMENT {
		state.tokenvec[left] = last_comment
		left += 1
	}

	/*
	 * sometimes we grab a 6th token to help determine the type of token 5.
	 * --> what does this mean?
	 */
	if left > LIBINJECTION_SQLI_MAX_TOKENS {
		left = LIBINJECTION_SQLI_MAX_TOKENS
	}

	return left, nil
}

/*
 * return true if SQLi, false if benign
 */
func (sqli *Sqli) libinjection_sqli_not_whitelist() bool {
	/*
	 * We assume we got a SQLi match
	 * This next part just helps reduce false positives.
	 *
	 */
	var ch byte
	state := sqli.state
	fingerprint := state.fingerprint
	tlen := len(fingerprint)

	if tlen > 1 && fingerprint[tlen-1] == TYPE_COMMENT {
		/*
		 * if ending comment is 'sp_password' then it's SQLi!
		 * MS Audit log apparently ignores anything with
		 * 'sp_password' in it. Unable to find primary reference to
		 * this "feature" of SQL Server but seems to be known SQLi
		 * technique
		 */
		if strings.Contains(state.s, "sp_password") {
			return true
		}
	}

	switch tlen {
	case 2:
		{
			/*
			 * case 2 are "very small SQLi" which make them
			 * hard to tell from normal input...
			 */

			if fingerprint[1] == TYPE_UNION {
				if state.stats_tokens == 2 {
					/* not sure why but 1U comes up in SQLi attack
					 * likely part of parameter splitting/etc.
					 * lots of reasons why "1 union" might be normal
					 * input, so beep only if other SQLi things are present
					 */
					/* it really is a number and 'union'
					 * other wise it has folding or comments
					 */
					return false
				} else {
					return true
				}
			}
			/*
			 * if 'comment' is '#' ignore.. too many FP
			 */
			if state.tokenvec[1].val[0] == '#' {
				return false
			}

			/*
			 * for fingerprint like 'nc', only comments of /x are treated
			 * as SQL... ending comments of "--" and "#" are not SQLi
			 */
			if state.tokenvec[0].Type == TYPE_BAREWORD &&
				state.tokenvec[1].Type == TYPE_COMMENT &&
				state.tokenvec[1].val[0] != '/' {
				return false
			}

			/*
			 * if '1c' ends with '/x' then it's SQLi
			 */
			if state.tokenvec[0].Type == TYPE_NUMBER &&
				state.tokenvec[1].Type == TYPE_COMMENT &&
				state.tokenvec[1].val[0] == '/' {
				return true
			}

			/*
			 * there are some odd base64-looking query string values
			 * 1234-ABCDEFEhfhihwuefi--
			 * which evaluate to "1c"... these are not SQLi
			 * but 1234-- probably is.
			 * Make sure the "1" in "1c" is actually a true decimal number
			 *
			 * Need to check -original- string since the folding step
			 * may have merged tokens, e.g. "1+FOO" is folded into "1"
			 *
			 * Note: evasion: 1*1--
			 */
			if state.tokenvec[0].Type == TYPE_NUMBER &&
				state.tokenvec[1].Type == TYPE_COMMENT {
				if state.stats_tokens > 2 {
					/* we have some folding going on, highly likely SQLi */
					return true
				}
				/*
				 * we check that next character after the number is either whitespace,
				 * or '/' or a '-' ==> SQLi.
				 */
				ch = state.s[state.tokenvec[0].Len]
				if ch <= 32 {
					/* next char was whitespace,e.g. "1234 --"
					 * this isn't exactly correct.. ideally we should skip over all whitespace
					 * but this seems to be ok for now
					 */
					return true
				}
				if ch == '/' && state.s[state.tokenvec[0].Len+1] == '*' {
					return true
				}
				if ch == '-' && state.s[state.tokenvec[0].Len+1] == '-' {
					return true
				}

				return false
			}

			/*
			 * detect obvious SQLi scans.. many people put '--' in plain text
			 * so only detect if input ends with '--', e.g. 1-- but not 1-- foo
			 */
			if (state.tokenvec[1].Len > 2) &&
				state.tokenvec[1].val[0] == '-' {
				return false
			}

			break
		} /* case 2 */
	case 3:
		{
			/*
			 * ...foo' + 'bar...
			 * no opening quote, no closing quote
			 * and each string has data
			 */

			if fingerprint == "sos" ||
				fingerprint == "s&s" {

				if (state.tokenvec[0].str_open == CHAR_NULL) &&
					(state.tokenvec[2].str_close == CHAR_NULL) &&
					(state.tokenvec[0].str_close == state.tokenvec[2].str_open) {
					/*
					 * if ....foo" + "bar....
					 */
					return true
				}
				if state.stats_tokens == 3 {
					return false
				}

				/*
				 * not SQLi
				 */
				return false
			} else if state.fingerprint == "s&n" ||
				state.fingerprint == "n&1" ||
				state.fingerprint == "1&1" ||
				state.fingerprint == "1&v" ||
				state.fingerprint == "1&s" {
				/*
				 * 'sexy and 17' not SQLi
				 * 'sexy and 17<18'  SQLi
				 */
				if state.stats_tokens == 3 {
					return false
				}
			} else if state.tokenvec[1].Type == TYPE_KEYWORD {
				keyword := strings.ToUpper(state.tokenvec[1].val)
				if (state.tokenvec[1].Len < 5) ||
					!(keyword == "INTO OUTFILE" || keyword == "INTO DUMPFILE") {
					/*
					 * if it's not "INTO OUTFILE", or "INTO DUMPFILE" (MySQL)
					 * then treat as safe
					 */
					return false
				}
			}
			break
		} /* case 3 */
	case 4:
		{
			/* NOVC, 1OVC */
			if state.fingerprint == "novc" || state.fingerprint == "1ovc" {
				if state.tokenvec[1].val == "!" &&
					state.tokenvec[2].Len == 0 &&
					state.tokenvec[3].val[0] == '#' {
					/*
					 * case where user enters !@# in password
					 */
					return false
				}
			}
			break
		} /* case 4 */
	case 5:
		{
			/* nothing right now */
			break
		} /* case 5 */
	} /* end switch */

	return true
}

func (sqli *Sqli) is_keyword(str string) bool {
	value := sql_keywords[strings.ToUpper(str)]

	if value == 0 || value != TYPE_FINGERPRINT {
		return false
	}
	return true
}

func (sqli *Sqli) libinjection_sqli_check_fingerprint() bool {
	return sqli.libinjection_sqli_blacklist() && sqli.libinjection_sqli_not_whitelist()
}

func (sqli *Sqli) libinjection_sqli_blacklist() bool {
	state := sqli.state
	l := len(state.fingerprint)

	if l > 0 && sqli.is_keyword(state.fingerprint) {
		return true
	}
	return false
}

func (sqli *Sqli) reparse_as_mysql() bool {
	state := sqli.state
	return (state.stats_comment_ddx + state.stats_comment_hash) > 0
}

/**
 *  Secondary API: Detect SQLi GIVEN a context.
 */
func (sqli *Sqli) libinjection_sqli_fingerprint(flags int) (string, error) {
	fplen := 0
	fp := strings.Builder{}

	/*
	 * reset state: needed since we may test single input multiples times:
	 * - as is
	 * - single quote mode
	 * - double quote mode
	 */
	state := newState(sqli.state.s, sqli.state.slen, flags)

	/* get fingerprint */
	fplen, err := sqli.libinjection_sqli_fold()
	if err != nil {
		return "", err
	}

	/*
	 * Check for magic PHP backquote comment If: * last token is of type
	 * "bareword" * And is quoted in a backtick * And isn't closed * And
	 * it's empty? Then convert it to comment
	 */
	if fplen > 2 && state.tokenvec[fplen-1].Type == TYPE_BAREWORD &&
		state.tokenvec[fplen-1].str_open == CHAR_TICK &&
		state.tokenvec[fplen-1].Len == 0 &&
		state.tokenvec[fplen-1].str_close == CHAR_NULL {
		state.tokenvec[fplen-1].Type = TYPE_COMMENT
	}

	/* copy fingerprint to String */
	for i := 0; i < fplen; i++ {
		fp.WriteByte(state.tokenvec[i].Type)
	}
	state.fingerprint = fp.String()

	/*
	 * check for 'X' in pattern, and then clear out all tokens
	 *
	 * this means parsing could not be done accurately due to pgsql's double
	 * comments or other syntax that isn't consistent. Should be very rare
	 * false positive
	 */
	if strings.IndexByte(state.fingerprint, TYPE_EVIL) != -1 {
		state.fingerprint = "X"
		token := newToken(TYPE_EVIL, 0, 0, string(TYPE_EVIL))
		replace := [8]*Token{token, nil, nil, nil, nil, nil, nil, nil}
		state.tokenvec = replace
	}

	return state.fingerprint, nil
}

func (sqli *Sqli) libinjection_is_sqli() bool {
	state := sqli.state
	s := state.s
	slen := state.slen
	sqlifingerprint := false

	if slen == 0 {
		state.fingerprint = ""
		return false
	}

	/* test input as-is */
	sqli.libinjection_sqli_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_ANSI)
	sqlifingerprint = sqli.libinjection_sqli_check_fingerprint()
	if sqlifingerprint {
		return true
	} else if sqli.reparse_as_mysql() {
		sqli.libinjection_sqli_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_MYSQL)
		sqlifingerprint = sqli.libinjection_sqli_check_fingerprint()
		if sqlifingerprint {
			return true
		}
	}

	/*
	 * if input contains single quote, pretend it starts with single quote
	 * example: admin' OR 1=1--  is tested as  'admin' OR 1=1--
	 */
	if strings.Contains(s, "'") {
		sqli.libinjection_sqli_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI)
		sqlifingerprint = sqli.libinjection_sqli_check_fingerprint()
		if sqlifingerprint {
			return true
		} else if sqli.reparse_as_mysql() {
			sqli.libinjection_sqli_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL)
			sqlifingerprint = sqli.libinjection_sqli_check_fingerprint()
			if sqlifingerprint {
				return true
			}
		}
	}

	/*
	 * same as above but with a double-quote "
	 */
	if strings.Contains(s, "\"") {
		sqli.libinjection_sqli_fingerprint(FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL)
		sqlifingerprint = sqli.libinjection_sqli_check_fingerprint()
		if sqlifingerprint {
			return true
		}
	}

	/* Not SQLi! */
	return false
}

func (sqli *Sqli) libinjection_sqli(input string) (bool, string) {
	sqli.state = newState(input, len(input), 0)
	issqli := sqli.libinjection_is_sqli()
	return issqli, sqli.state.fingerprint
}

func libinjection_sqli_lookup_word(str string) byte {
	return sql_keywords[strings.ToUpper(str)]
}
