package libinjection

import (
	"bytes"
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

type stoken_t struct {
	Pos      int
	Len      int
	Count    int
	Type     byte
	StrOpen  byte
	StrClose byte
	Val      []byte //max 32!
}

type keyword_t struct {
	Word string
	Type byte
}

type libinjection_sqli_state struct {
	/*
	 * input, does not need to be null terminated.
	 * it is also not modified.
	 */
	S []byte
	/*
	 * input length
	 */
	Slen  int
	Flags int
	/*
	 * pos is the index in the string during tokenization
	 */
	Pos int
	/*
	 * Pointer to token position in tokenvec, above
	 */
	Current *stoken_t

	/*
	 * fingerprint pattern c-string
	 * +1 for ending null
	 * Minimum of 8 bytes to add gcc's -fstack-protector to work
	 */
	Fingerprint []byte

	/*
	 * Line number of code that said decided if the input was SQLi or
	 * not.  Most of the time it's line that said "it's not a matching
	 * fingerprint" but there is other logic that sometimes approves
	 * an input. This is only useful for debugging.
	 *
	 */
	Reason int

	/* Number of ddw (dash-dash-white) comments
	 * These comments are in the form of
	 *   '--[whitespace]' or '--[EOF]'
	 *
	 * All databases treat this as a comment.
	 */
	Stats_comment_ddw int

	/* Number of ddx (dash-dash-[notwhite]) comments
	 *
	 * ANSI SQL treats these are comments, MySQL treats this as
	 * two unary operators '-' '-'
	 *
	 * If you are parsing result returns FALSE and
	 * stats_comment_dd > 0, you should reparse with
	 * COMMENT_MYSQL
	 *
	 */
	Stats_comment_ddx int

	/*
	 * c-style comments found  /x .. x/
	 */
	Stats_comment_c int

	/* '#' operators or MySQL EOL comments found
	 *
	 */
	Stats_comment_hash int

	/*
	 * number of tokens folded away
	 */
	Stats_folds int

	/*
	 * total tokens processed
	 */
	Stats_tokens int

	// Apparently it does nothing
	Userdata interface{}

	Tokenvec []*stoken_t
}

func (sql_state *libinjection_sqli_state) Lookup(lookup_type int, str []byte, l int) byte {
	if lookup_type == LOOKUP_FINGERPRINT {
		if libinjection_sqli_check_fingerprint(sql_state) {
			return 'X'
		} else {
			return 0x00
		}
	} else {
		return bsearch_keyword_type(str, l, sql_keywords, sql_keywords_sz)
	}
}

/**
 *
 *
 *
 * Porting Notes:
 *  given a mapping/hash of string to char
 *  this is just
 *    typecode = mapping[key.upper()]
 */
func bsearch_keyword_type(key []byte, klen int, keywords []keyword_t, numb int) byte {
	left := 0
	right := numb - 1
	for left < right {
		pos := (left + right) >> 1
		if cstrcasecmp(keywords[left].Word, key, klen) == 0 {
			left = pos + 1
		} else {
			right = pos
		}
	}
	if (left == right) && cstrcasecmp(keywords[left].Word, key, klen) == 0 {
		return keywords[left].Type
	} else {
		return CHAR_NULL
	}
}

func is_keyword(key []byte, klen int) byte {
	return bsearch_keyword_type(key, klen, sql_keywords, sql_keywords_sz)
}

func st_assign_char(st *stoken_t, stype byte, pos int, l int, value byte) {
	/* done to eliminate unused warning */
	st.Type = stype
	st.Pos = pos
	st.Len = 1
	st.Val = []byte{value}
}

func st_assign(st *stoken_t, stype byte, pos int, l int, value []byte) {
	const MSIZE = LIBINJECTION_SQLI_TOKEN_SIZE
	last := MSIZE - 1
	if l < MSIZE {
		last = l
	}
	st.Type = stype
	st.Pos = pos
	st.Len = last
	st.Val = value[:last]
}

func st_is_arithmetic_op(st *stoken_t) bool {
	ch := st.Val[0]
	return st.Type == TYPE_OPERATOR && st.Len == 1 && (ch == '*' || ch == '/' || ch == '-' || ch == '+' || ch == '%')
}

func st_is_unary_op(st *stoken_t) bool {
	str := st.Val
	l := st.Len

	if st.Type != TYPE_OPERATOR {
		return false
	}

	switch l {
	case 1:
		return str[0] == '+' || str[0] == '-' || str[0] == '!' || str[0] == '~'
	case 2:
		return str[0] == '!' && str[1] == '!'
	case 3:
		return cstrcasecmp("NOT", str, 3) == 0
	default:
		return false
	}
}

/* Parsers
 *
 *
 */

func parse_white(sf *libinjection_sqli_state) int {
	return sf.Pos + 1
}

func parse_operator1(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos

	st_assign_char(sf.Current, TYPE_OPERATOR, pos, 1, cs[pos])
	return pos + 1
}

func parse_other(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos

	st_assign_char(sf.Current, TYPE_UNKNOWN, pos, 1, cs[pos])
	return pos + 1
}

func parse_char(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos

	st_assign_char(sf.Current, cs[pos], pos, 1, cs[pos])
	return pos + 1
}

//TODO this might be all wrong
func parse_eol_comment(sf *libinjection_sqli_state) int {
	cs := sf.S
	pos := sf.Pos
	slen := sf.Slen

	endpos := bytes.IndexByte(cs[pos:pos+slen], '\n')
	if endpos == -1 {
		st_assign(sf.Current, TYPE_COMMENT, pos, slen-pos, cs[pos:])
		return slen
	} else {
		st_assign(sf.Current, TYPE_COMMENT, pos, endpos-pos, cs[pos:])
		//return ((endpos - cs) + 1)
		return 0
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
		st_assign_char(sf.Current, TYPE_OPERATOR, sf.Pos, 1, '#')
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
		st_assign_char(sf.Current, TYPE_OPERATOR, pos, 1, '-')
		return pos + 1
	}
}

/** This detects MySQL comments, comments that
 * start with /x!   We just ban these now but
 * previously we attempted to parse the inside
 *
 * For reference:
 * the form of /x![anything]x/ or /x!12345[anything] x/
 *
 * Mysql 3 (maybe 4), allowed this:
 *    /x!0selectx/ 1;
 * where 0 could be any number.
 *
 * The last version of MySQL 3 was in 2003.
 * It is unclear if the MySQL 3 syntax was allowed
 * in MySQL 4.  The last version of MySQL 4 was in 2008
 *
 */
func is_mysql_comment(cs []byte, l int, pos int) bool {
	/* so far...
	 * cs[pos] == '/' && cs[pos+1] == '*'
	 */

	if pos+2 >= l {
		/* not a mysql comment */
		return false
	}

	if cs[pos+2] != '!' {
		/* not a mysql comment */
		return false
	}

	/*
	 * this is a mysql comment
	 *  got "/x!"
	 */
	return true
}

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

	st_assign(sf.Current, byte(ctype), pos, clen, cs[pos:])
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
		st_assign(sf.Current, TYPE_NUMBER, pos, 2, cs[pos:])
		return pos + 2
	} else {
		st_assign_char(sf.Current, TYPE_BACKSLASH, pos, 1, cs[pos])
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
		st_assign(sf.Current, TYPE_OPERATOR, pos, 3, cs[pos:])
		return pos + 3
	}

	ch = sf.Lookup(LOOKUP_OPERATOR, cs[pos:], 2)
	if ch != CHAR_NULL {
		st_assign(sf.Current, ch, pos, 2, cs[pos:])
		return pos + 2
	}

	/*
	 * not an operator.. what to do with the two
	 * characters we got?
	 */

	if cs[pos] == ':' {
		/* ':' is not an operator */
		st_assign(sf.Current, TYPE_COLON, pos, 1, cs[pos:])
		return pos + 1
	} else {
		/*
		 * must be a single char operator
		 */
		return parse_operator1(sf)
	}
}

/*
 * Ok!   "  \"   "  one backslash = escaped!
 *       " \\"   "  two backslash = not escaped!
 *       "\\\"   "  three backslash = escaped!
 */
func is_backslash_escaped(str []byte) bool {
	var ptr int
	end := clen(str) - 1
	for ptr = end; ptr >= 0; ptr-- {
		if str[ptr] != '\\' {
			break
		}
	}
	/* if number of backslashes is odd, it is escaped */

	return (end-ptr)%2 != 0
}

func is_double_delim_escaped(cur []byte) bool {
	return 1 < clen(cur)-1 && cur[1] == cur[0]
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
			st_assign(st, TYPE_STRING, pos+offset, l-pos-offset, cs[pos+offset:])
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
			st_assign(st, TYPE_STRING, pos+offset, qpos-(pos+offset), cs[pos+offset:])
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
		st_assign(sf.Current, TYPE_STRING, pos+3, slen-pos-3, cs[pos+3:])
		sf.Current.StrOpen = 'q'
		sf.Current.StrClose = CHAR_NULL
		return slen
	} else {
		st_assign(sf.Current, TYPE_STRING, pos+3, strend-pos-3, cs[pos+3:])
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
	st_assign(sf.Current, TYPE_NUMBER, pos, wlen+3, cs[pos:])
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
	st_assign(sf.Current, TYPE_NUMBER, pos, wlen+3, cs[pos:])
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
		st_assign(sf.Current, TYPE_BAREWORD, pos, sf.Slen-pos, cs[pos:])
		return sf.Slen
	} else {
		st_assign(sf.Current, TYPE_BAREWORD, pos, endptr-pos+1, cs[pos:])
		return endptr + 1
	}
}

func parse_word(sf *libinjection_sqli_state) int {
	var ch, delim byte
	cs := sf.S
	pos := sf.Pos
	wlen := strlencspn(cs[pos:], sf.Slen-pos, " []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r\"\240\000")

	st_assign(sf.Current, TYPE_BAREWORD, pos, wlen, cs[pos:])

	/* now we need to look inside what we good for "." and "`"
	 * and see if what is before is a keyword or not
	 */
	for i := 0; i < sf.Current.Len; {
		i++
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
				st_assign(sf.Current, ch, pos, i, cs[pos:])
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
		st_assign(sf.Current, TYPE_VARIABLE, pos, 0, cs[pos:])
		return pos
	} else {
		st_assign(sf.Current, TYPE_VARIABLE, pos, xlen, cs[pos:])
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
		st_assign_char(sf.Current, TYPE_BAREWORD, pos, 1, '$')
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
				st_assign(sf.Current, TYPE_STRING, pos+2, slen-(pos+2), cs[pos+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = CHAR_NULL
				return slen
			} else {
				st_assign(sf.Current, TYPE_STRING, pos+2, (strend - pos + 2), cs[pos+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = '$'
				return strend + 2
			}
		} else {
			/* ok it's not a number or '$$', but maybe it's pgsql "$ quoted strings" */
			xlen = strlenspn(cs[pos+1:], slen-pos-1, "abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if xlen == 0 {
				/* hmm it's "$" _something_ .. just add $ and keep going*/
				st_assign_char(sf.Current, TYPE_BAREWORD, pos, 1, '$')
				return pos + 1
			}
			/* we have $foobar????? */
			/* is it $foobar$ */
			if pos+xlen+1 == slen || cs[pos+xlen+1] != '$' {
				/* not $foobar$, or fell off edge */
				st_assign_char(sf.Current, TYPE_BAREWORD, pos, 1, '$')
				return pos + 1
			}

			/* we have $foobar$ ... find it again */
			strend = bytes.IndexAny(cs[pos+xlen+2:], string(cs[pos:pos+xlen+2]))

			// TODO check
			if strend > slen {
				/* fell off edge */
				st_assign(sf.Current, TYPE_STRING, pos+xlen+2, slen-pos-xlen-2, cs[pos+xlen+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = CHAR_NULL
				return slen
			} else {
				/* got one */
				st_assign(sf.Current, TYPE_STRING, pos+xlen+2, (strend - pos + xlen + 2), cs[pos+xlen+2:])
				sf.Current.StrOpen = '$'
				sf.Current.StrClose = '$'
				return strend + xlen + 2
			}
		}
	} else if xlen == 1 && cs[pos+1] == '.' {
		/* $. should parsed as a word */
		return parse_word(sf)
	} else {
		st_assign(sf.Current, TYPE_NUMBER, pos, 1+xlen, cs[pos:])
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
				st_assign(sf.Current, TYPE_BAREWORD, pos, 2, cs[pos:])
				return pos + 2
			} else {
				st_assign(sf.Current, TYPE_NUMBER, pos, 2+xlen, cs[pos:])
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
			st_assign_char(sf.Current, TYPE_DOT, start, 1, '.')
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
		st_assign(sf.Current, TYPE_BAREWORD, start, pos-start, cs[start:])
	} else {
		st_assign(sf.Current, TYPE_NUMBER, start, pos-start, cs[start:])
	}
	return pos
}

func libinjection_sqli_tokenize(sf *libinjection_sqli_state) bool {
	current := sf.Current
	s := sf.S
	slen := sf.Slen

	if slen == 0 {
		return false
	}

	st_clear(&current)
	sf.Current = current

	/*
	 * if we are at beginning of string
	 *  and in single-quote or double quote mode
	 *  then pretend the input starts with a quote
	 */
	if sf.Pos == 0 && (sf.Flags&(FLAG_QUOTE_SINGLE|FLAG_QUOTE_DOUBLE) == 1) {
		sf.Pos = parse_string_core(s, slen, 0, current, flag2delim(sf.Flags), 0)
		sf.Stats_tokens += 1
		return true
	}

	for sf.Pos < slen {

		/*
		 * get current character
		 */
		ch := (s[sf.Pos])

		/*
		 * look up the parser, and call it
		 *
		 * Porting Note: this is mapping of char to function
		 *   charparsers[ch]()
		 */
		fnptr := char_parse_map[ch]

		sf.Pos = fnptr(sf)

		/*
		 *
		 */
		if current.Type != CHAR_NULL {
			sf.Stats_tokens += 1
			return true
		}
	}
	return false
}

func libinjection_sqli_init(s []byte, l int, flags int) *libinjection_sqli_state {
	if flags == 0 {
		flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI
	}
	tokens := []*stoken_t{}
	for i := 0; i < 8; i++ {
		tokens = append(tokens, new(stoken_t))
	}
	return &libinjection_sqli_state{
		S:           s,
		Slen:        l,
		Userdata:    0,
		Flags:       flags,
		Current:     new(stoken_t),
		Tokenvec:    tokens,
		Fingerprint: make([]byte, 8),
	}
}

func libinjection_sqli_reset(sf *libinjection_sqli_state, flags int) {
	userdata := sf.Userdata

	if flags == 0 {
		flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI
	}
	*sf = *libinjection_sqli_init(sf.S, sf.Slen, flags)
	sf.Userdata = userdata
}

/** See if two tokens can be merged since they are compound SQL phrases.
 *
 * This takes two tokens, and, if they are the right type,
 * merges their values together.  Then checks to see if the
 * new value is special using the PHRASES mapping.
 *
 * Example: "UNION" + "ALL" ==> "UNION ALL"
 *
 * C Security Notes: this is safe to use C-strings (null-terminated)
 *  since the types involved by definition do not have embedded nulls
 *  (e.g. there is no keyword with embedded null)
 *
 * Porting Notes: since this is C, it's oddly complicated.
 *  This is just:  multikeywords[token.Value + ' ' + token2.Value]
 *
 */
func syntax_merge_words(sf *libinjection_sqli_state, a *stoken_t, b *stoken_t) bool {
	var sz1, sz2, sz3 int
	var tmp []byte
	var ch byte

	/* first token is of right type? */
	if !(a.Type == TYPE_KEYWORD ||
		a.Type == TYPE_BAREWORD ||
		a.Type == TYPE_OPERATOR ||
		a.Type == TYPE_UNION ||
		a.Type == TYPE_FUNCTION ||
		a.Type == TYPE_EXPRESSION ||
		a.Type == TYPE_TSQL ||
		a.Type == TYPE_SQLTYPE) {
		return false
	}

	if !(b.Type == TYPE_KEYWORD ||
		b.Type == TYPE_BAREWORD ||
		b.Type == TYPE_OPERATOR ||
		b.Type == TYPE_UNION ||
		b.Type == TYPE_FUNCTION ||
		b.Type == TYPE_EXPRESSION ||
		b.Type == TYPE_TSQL ||
		b.Type == TYPE_SQLTYPE ||
		b.Type == TYPE_LOGIC_OPERATOR) {
		return false
	}

	sz1 = a.Len
	sz2 = b.Len
	sz3 = sz1 + sz2 + 1                      /* +1 for space in the middle */
	if sz3 >= LIBINJECTION_SQLI_TOKEN_SIZE { /* make sure there is room for ending null */
		return false
	}
	/*
	 * oddly annoying  last.Val + ' ' + current.Val
	 */
	tmp = append(a.Val[sz1:], tmp[sz1:]...)
	//memcpy(tmp, a.Val, sz1)
	tmp[sz1] = ' '
	tmp = append(tmp[:sz1+1], b.Val[sz2:]...)
	//memcpy(tmp+sz1+1, b.Val, sz2)
	tmp[sz3] = CHAR_NULL
	ch = sf.Lookup(LOOKUP_WORD, tmp, sz3)

	if ch != CHAR_NULL {
		st_assign(a, ch, a.Pos, sz3, tmp)
		return true
	} else {
		return false
	}
}

func libinjection_sqli_fold(sf *libinjection_sqli_state) int {
	var last_comment *stoken_t

	/* POS is the position of where the NEXT token goes */
	pos := 0

	/* LEFT is a count of how many tokens that are already
	   folded or processed (i.e. part of the fingerprint) */
	left := 0

	more := true

	st_clear(&last_comment)

	/* Skip all initial comments, right-parens ( and unary operators
	 *
	 */
	sf.Current = (sf.Tokenvec[0])
	for !more {
		if libinjection_sqli_tokenize(sf) {
			more = true
		}
		if !(sf.Current.Type == TYPE_COMMENT ||
			sf.Current.Type == TYPE_LEFTPARENS ||
			sf.Current.Type == TYPE_SQLTYPE ||
			st_is_unary_op(sf.Current)) {
			break
		}
	}

	if !more {
		/* If input was only comments, unary or (, then exit */
		return 0
	} else {
		/* it's some other token */
		pos += 1
	}

	for {
		//FOLD_DEBUG

		/* do we have all the max number of tokens?  if so do
		 * some special cases for 5 tokens
		 */
		if pos >= LIBINJECTION_SQLI_MAX_TOKENS {
			if (sf.Tokenvec[0].Type == TYPE_NUMBER &&
				(sf.Tokenvec[1].Type == TYPE_OPERATOR || sf.Tokenvec[1].Type == TYPE_COMMA) &&
				sf.Tokenvec[2].Type == TYPE_LEFTPARENS &&
				sf.Tokenvec[3].Type == TYPE_NUMBER &&
				sf.Tokenvec[4].Type == TYPE_RIGHTPARENS) ||
				(sf.Tokenvec[0].Type == TYPE_BAREWORD &&
					sf.Tokenvec[1].Type == TYPE_OPERATOR &&
					sf.Tokenvec[2].Type == TYPE_LEFTPARENS &&
					(sf.Tokenvec[3].Type == TYPE_BAREWORD || sf.Tokenvec[3].Type == TYPE_NUMBER) &&
					sf.Tokenvec[4].Type == TYPE_RIGHTPARENS) ||
				(sf.Tokenvec[0].Type == TYPE_NUMBER &&
					sf.Tokenvec[1].Type == TYPE_RIGHTPARENS &&
					sf.Tokenvec[2].Type == TYPE_COMMA &&
					sf.Tokenvec[3].Type == TYPE_LEFTPARENS &&
					sf.Tokenvec[4].Type == TYPE_NUMBER) ||
				(sf.Tokenvec[0].Type == TYPE_BAREWORD &&
					sf.Tokenvec[1].Type == TYPE_RIGHTPARENS &&
					sf.Tokenvec[2].Type == TYPE_OPERATOR &&
					sf.Tokenvec[3].Type == TYPE_LEFTPARENS &&
					sf.Tokenvec[4].Type == TYPE_BAREWORD) {
				if pos > LIBINJECTION_SQLI_MAX_TOKENS {
					st_copy((sf.Tokenvec[1]), (sf.Tokenvec[LIBINJECTION_SQLI_MAX_TOKENS]))
					pos = 2
					left = 0
				} else {
					pos = 1
					left = 0
				}
			}
		}

		if !more || left >= LIBINJECTION_SQLI_MAX_TOKENS {
			left = pos
			break
		}

		/* get up to two tokens */
		for more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos-left) < 2 {
			*sf.Current = *sf.Tokenvec[pos]
			if libinjection_sqli_tokenize(sf) {
				more = true
			} else {
				more = false
			}
			if more {
				if sf.Current.Type == TYPE_COMMENT {
					st_copy(last_comment, sf.Current)
				} else {
					last_comment.Type = CHAR_NULL
					pos += 1
				}
			}
		}
		//FOLD_DEBUG
		/* did we get 2 tokens? if not then we are done */
		if pos-left < 2 {
			left = pos
			continue
		}

		/* FOLD: "ss" . "s"
		 * "foo" "bar" is valid SQL
		 * just ignore second string
		 */
		if sf.Tokenvec[left].Type == TYPE_STRING && sf.Tokenvec[left+1].Type == TYPE_STRING {
			pos -= 1
			sf.Stats_folds += 1
			continue
		} else if sf.Tokenvec[left].Type == TYPE_SEMICOLON && sf.Tokenvec[left+1].Type == TYPE_SEMICOLON {
			/* not sure how various engines handle
			 * 'select 1;;drop table foo' or
			 * 'select 1; /x foo x/; drop table foo'
			 * to prevent surprises, just fold away repeated semicolons
			 */
			pos -= 1
			sf.Stats_folds += 1
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_OPERATOR ||
			sf.Tokenvec[left].Type == TYPE_LOGIC_OPERATOR) &&
			(st_is_unary_op(sf.Tokenvec[left+1]) ||
				sf.Tokenvec[left+1].Type == TYPE_SQLTYPE) {
			pos -= 1
			sf.Stats_folds += 1
			left = 0
			continue
		} else if sf.Tokenvec[left].Type == TYPE_LEFTPARENS &&
			st_is_unary_op(sf.Tokenvec[left+1]) {
			pos -= 1
			sf.Stats_folds += 1
			if left > 0 {
				left -= 1
			}
			continue
		} else if syntax_merge_words(sf, sf.Tokenvec[left], sf.Tokenvec[left+1]) {
			pos -= 1
			sf.Stats_folds += 1
			if left > 0 {
				left -= 1
			}
			continue
		} else if sf.Tokenvec[left].Type == TYPE_SEMICOLON &&
			sf.Tokenvec[left+1].Type == TYPE_FUNCTION &&
			(sf.Tokenvec[left+1].Val[0] == 'I' ||
				sf.Tokenvec[left+1].Val[0] == 'i') &&
			(sf.Tokenvec[left+1].Val[1] == 'F' ||
				sf.Tokenvec[left+1].Val[1] == 'f') {
			/* IF is normally a function, except in Transact-SQL where it can be used as a
			 * standalone control flow operator, e.g. ; IF 1=1 ...
			 * if found after a semicolon, convert from 'f' type to 'T' type
			 */
			sf.Tokenvec[left+1].Type = TYPE_TSQL
			/* left += 2; */
			continue /* reparse everything, but we probably can advance left, and pos */
		} else if (sf.Tokenvec[left].Type == TYPE_BAREWORD || sf.Tokenvec[left].Type == TYPE_VARIABLE) &&
			sf.Tokenvec[left+1].Type == TYPE_LEFTPARENS && (
		/* TSQL functions but common enough to be column names */
		cstrcasecmp("USER_ID", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("USER_NAME", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||

			/* Function in MYSQL */
			cstrcasecmp("DATABASE", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("PASSWORD", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("USER", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||

			/* Mysql words that act as a variable and are a function */

			/* TSQL current_users is fake-variable */
			/* http://msdn.microsoft.com/en-us/library/ms176050.aspx */
			cstrcasecmp("CURRENT_USER", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("CURRENT_DATE", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("CURRENT_TIME", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("CURRENT_TIMESTAMP", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("LOCALTIME", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("LOCALTIMESTAMP", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0) {

			/* pos is the same
			 * other conversions need to go here... for instance
			 * password CAN be a function, coalesce CAN be a function
			 */
			sf.Tokenvec[left].Type = TYPE_FUNCTION
			continue
		} else if sf.Tokenvec[left].Type == TYPE_KEYWORD && (cstrcasecmp("IN", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("NOT IN", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0) {

			if sf.Tokenvec[left+1].Type == TYPE_LEFTPARENS {
				/* got .... IN ( ...  (or 'NOT IN')
				 * it's an operator
				 */
				sf.Tokenvec[left].Type = TYPE_OPERATOR
			} else {
				/*
				 * it's a nothing
				 */
				sf.Tokenvec[left].Type = TYPE_BAREWORD
			}

			/* "IN" can be used as "IN BOOLEAN MODE" for mysql
			 *  in which case merging of words can be done later
			 * other wise it acts as an equality operator __ IN (values..)
			 *
			 * here we got "IN" "(" so it's an operator.
			 * also back track to handle "NOT IN"
			 * might need to do the same with like
			 * two use cases   "foo" LIKE "BAR" (normal operator)
			 *  "foo" = LIKE(1,2)
			 */
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_OPERATOR) && (cstrcasecmp("LIKE", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 ||
			cstrcasecmp("NOT LIKE", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0) {
			if sf.Tokenvec[left+1].Type == TYPE_LEFTPARENS {
				/* SELECT LIKE(...
				 * it's a function
				 */
				sf.Tokenvec[left].Type = TYPE_FUNCTION
			}
		} else if sf.Tokenvec[left].Type == TYPE_SQLTYPE &&
			(sf.Tokenvec[left+1].Type == TYPE_BAREWORD ||
				sf.Tokenvec[left+1].Type == TYPE_NUMBER ||
				sf.Tokenvec[left+1].Type == TYPE_SQLTYPE ||
				sf.Tokenvec[left+1].Type == TYPE_LEFTPARENS ||
				sf.Tokenvec[left+1].Type == TYPE_FUNCTION ||
				sf.Tokenvec[left+1].Type == TYPE_VARIABLE ||
				sf.Tokenvec[left+1].Type == TYPE_STRING) {
			cp := &sf.Tokenvec[left+1]
			sf.Tokenvec[left] = *cp
			pos -= 1
			sf.Stats_folds += 1
			left = 0
			continue
		} else if sf.Tokenvec[left].Type == TYPE_COLLATE &&
			sf.Tokenvec[left+1].Type == TYPE_BAREWORD {
			/*
			 * there are too many collation types.. so if the bareword has a "_"
			 * then it's TYPE_SQLTYPE
			 */
			if !bytes.ContainsRune(sf.Tokenvec[left+1].Val, '_') {
				sf.Tokenvec[left+1].Type = TYPE_SQLTYPE
				left = 0
			}
		} else if sf.Tokenvec[left].Type == TYPE_BACKSLASH {
			if st_is_arithmetic_op((sf.Tokenvec[left+1])) {
				/* very weird case in TSQL where '\%1' is parsed as '0 % 1', etc */
				sf.Tokenvec[left].Type = TYPE_NUMBER
			} else {
				/* just ignore it.. Again T-SQL seems to parse \1 as "1" */
				st_copy(sf.Tokenvec[left], sf.Tokenvec[left+1])
				pos -= 1
				sf.Stats_folds += 1
			}
			left = 0
			continue
		} else if sf.Tokenvec[left].Type == TYPE_LEFTPARENS &&
			sf.Tokenvec[left+1].Type == TYPE_LEFTPARENS {
			pos -= 1
			left = 0
			sf.Stats_folds += 1
			continue
		} else if sf.Tokenvec[left].Type == TYPE_RIGHTPARENS &&
			sf.Tokenvec[left+1].Type == TYPE_RIGHTPARENS {
			pos -= 1
			left = 0
			sf.Stats_folds += 1
			continue
		} else if sf.Tokenvec[left].Type == TYPE_LEFTBRACE &&
			sf.Tokenvec[left+1].Type == TYPE_BAREWORD {

			/*
			 * MySQL Degenerate case --
			 *
			 *   select { ``.``.id };  -- valid !!!
			 *   select { ``.``.``.id };  -- invalid
			 *   select ``.``.id; -- invalid
			 *   select { ``.id }; -- invalid
			 *
			 * so it appears {``.``.id} is a magic case
			 * I suspect this is "current database, current table, field id"
			 *
			 * The folding code can't look at more than 3 tokens, and
			 * I don't want to make two passes.
			 *
			 * Since "{ ``" so rare, we are just going to blacklist it.
			 *
			 * Highly likely this will need revisiting!
			 *
			 * CREDIT @rsalgado 2013-11-25
			 */
			if sf.Tokenvec[left+1].Len == 0 {
				sf.Tokenvec[left+1].Type = TYPE_EVIL
				return (int)(left + 2)
			}
			/* weird ODBC / MYSQL  {foo expr} -. expr
			 * but for this rule we just strip away the "{ foo" part
			 */
			left = 0
			pos -= 2
			sf.Stats_folds += 2
			continue
		} else if sf.Tokenvec[left+1].Type == TYPE_RIGHTBRACE {
			pos -= 1
			left = 0
			sf.Stats_folds += 1
			continue
		}

		/* all cases of handing 2 tokens is done
		   and nothing matched.  Get one more token
		*/
		//FOLD_DEBUG
		for more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && pos-left < 3 {
			sf.Current = (sf.Tokenvec[pos])
			more = libinjection_sqli_tokenize(sf)
			if more {
				if sf.Current.Type == TYPE_COMMENT {
					st_copy(last_comment, sf.Current)
				} else {
					last_comment.Type = CHAR_NULL
					pos += 1
				}
			}
		}

		/* do we have three tokens? If not then we are done */
		if pos-left < 3 {
			left = pos
			continue
		}

		/*
		 * now look for three token folding
		 */
		if sf.Tokenvec[left].Type == TYPE_NUMBER &&
			sf.Tokenvec[left+1].Type == TYPE_OPERATOR &&
			sf.Tokenvec[left+2].Type == TYPE_NUMBER {
			pos -= 2
			left = 0
			continue
		} else if sf.Tokenvec[left].Type == TYPE_OPERATOR &&
			sf.Tokenvec[left+1].Type != TYPE_LEFTPARENS &&
			sf.Tokenvec[left+2].Type == TYPE_OPERATOR {
			left = 0
			pos -= 2
			continue
		} else if sf.Tokenvec[left].Type == TYPE_LOGIC_OPERATOR &&
			sf.Tokenvec[left+2].Type == TYPE_LOGIC_OPERATOR {
			pos -= 2
			left = 0
			continue
		} else if sf.Tokenvec[left].Type == TYPE_VARIABLE &&
			sf.Tokenvec[left+1].Type == TYPE_OPERATOR &&
			(sf.Tokenvec[left+2].Type == TYPE_VARIABLE ||
				sf.Tokenvec[left+2].Type == TYPE_NUMBER ||
				sf.Tokenvec[left+2].Type == TYPE_BAREWORD) {
			pos -= 2
			left = 0
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_BAREWORD ||
			sf.Tokenvec[left].Type == TYPE_NUMBER) &&
			sf.Tokenvec[left+1].Type == TYPE_OPERATOR &&
			(sf.Tokenvec[left+2].Type == TYPE_NUMBER ||
				sf.Tokenvec[left+2].Type == TYPE_BAREWORD) {
			pos -= 2
			left = 0
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_BAREWORD ||
			sf.Tokenvec[left].Type == TYPE_NUMBER ||
			sf.Tokenvec[left].Type == TYPE_VARIABLE ||
			sf.Tokenvec[left].Type == TYPE_STRING) &&
			sf.Tokenvec[left+1].Type == TYPE_OPERATOR &&
			streq(sf.Tokenvec[left+1].Val, "::") &&
			sf.Tokenvec[left+2].Type == TYPE_SQLTYPE {
			pos -= 2
			left = 0
			sf.Stats_folds += 2
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_BAREWORD ||
			sf.Tokenvec[left].Type == TYPE_NUMBER ||
			sf.Tokenvec[left].Type == TYPE_STRING ||
			sf.Tokenvec[left].Type == TYPE_VARIABLE) &&
			sf.Tokenvec[left+1].Type == TYPE_COMMA &&
			(sf.Tokenvec[left+2].Type == TYPE_NUMBER ||
				sf.Tokenvec[left+2].Type == TYPE_BAREWORD ||
				sf.Tokenvec[left+2].Type == TYPE_STRING ||
				sf.Tokenvec[left+2].Type == TYPE_VARIABLE) {
			pos -= 2
			left = 0
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_EXPRESSION ||
			sf.Tokenvec[left].Type == TYPE_GROUP ||
			sf.Tokenvec[left].Type == TYPE_COMMA) &&
			st_is_unary_op(sf.Tokenvec[left+1]) &&
			sf.Tokenvec[left+2].Type == TYPE_LEFTPARENS {
			/* got something like SELECT + (, LIMIT + (
			 * remove unary operator
			 */
			st_copy(sf.Tokenvec[left+1], sf.Tokenvec[left+2])
			pos -= 1
			left = 0
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_KEYWORD ||
			sf.Tokenvec[left].Type == TYPE_EXPRESSION ||
			sf.Tokenvec[left].Type == TYPE_GROUP) &&
			st_is_unary_op(sf.Tokenvec[left+1]) &&
			(sf.Tokenvec[left+2].Type == TYPE_NUMBER ||
				sf.Tokenvec[left+2].Type == TYPE_BAREWORD ||
				sf.Tokenvec[left+2].Type == TYPE_VARIABLE ||
				sf.Tokenvec[left+2].Type == TYPE_STRING ||
				sf.Tokenvec[left+2].Type == TYPE_FUNCTION) {
			/* remove unary operators
			 * select - 1
			 */
			st_copy(sf.Tokenvec[left+1], sf.Tokenvec[left+2])
			pos -= 1
			left = 0
			continue
		} else if sf.Tokenvec[left].Type == TYPE_COMMA &&
			st_is_unary_op(sf.Tokenvec[left+1]) &&
			(sf.Tokenvec[left+2].Type == TYPE_NUMBER ||
				sf.Tokenvec[left+2].Type == TYPE_BAREWORD ||
				sf.Tokenvec[left+2].Type == TYPE_VARIABLE ||
				sf.Tokenvec[left+2].Type == TYPE_STRING) {
			/*
			 * interesting case    turn ", -1"  .> ",1" PLUS we need to back up
			 * one token if possible to see if more folding can be done
			 * "1,-1" -. "1"
			 */
			st_copy(sf.Tokenvec[left+1], sf.Tokenvec[left+2])
			left = 0
			/* pos is >= 3 so this is safe */
			if pos < 3 {
				// TODO shall we use errors?
				return -1
			}
			pos -= 3
			continue
		} else if sf.Tokenvec[left].Type == TYPE_COMMA &&
			st_is_unary_op(sf.Tokenvec[left+1]) &&
			sf.Tokenvec[left+2].Type == TYPE_FUNCTION {

			/* Separate case from above since you end up with
			 * 1,-sin(1) -. 1 (1)
			 * Here, just do
			 * 1,-sin(1) -. 1,sin(1)
			 * just remove unary operator
			 */
			st_copy(sf.Tokenvec[left+1], sf.Tokenvec[left+2])
			pos -= 1
			left = 0
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_BAREWORD) &&
			(sf.Tokenvec[left+1].Type == TYPE_DOT) &&
			(sf.Tokenvec[left+2].Type == TYPE_BAREWORD) {
			/* ignore the '.n'
			 * typically is this databasename.table
			 */
			if pos < 3 {
				// TODO assert error
				return -1
			}
			pos -= 2
			left = 0
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_EXPRESSION) &&
			(sf.Tokenvec[left+1].Type == TYPE_DOT) &&
			(sf.Tokenvec[left+2].Type == TYPE_BAREWORD) {
			/* select . `foo` -. select `foo` */
			st_copy(sf.Tokenvec[left+1], sf.Tokenvec[left+2])
			pos -= 1
			left = 0
			continue
		} else if (sf.Tokenvec[left].Type == TYPE_FUNCTION) &&
			(sf.Tokenvec[left+1].Type == TYPE_LEFTPARENS) &&
			(sf.Tokenvec[left+2].Type != TYPE_RIGHTPARENS) {
			/*
			 * whats going on here
			 * Some SQL functions like USER() have 0 args
			 * if we get User(foo), then User is not a function
			 * This should be expanded since it eliminated a lot of false
			 * positives.
			 */
			if cstrcasecmp("USER", sf.Tokenvec[left].Val, sf.Tokenvec[left].Len) == 0 {
				sf.Tokenvec[left].Type = TYPE_BAREWORD
			}
		}

		/* no folding -- assume left-most token is
		   is good, now use the existing 2 tokens --
		   do not get another
		*/

		left += 1

	} /* while(1) */

	/* if we have 4 or less tokens, and we had a comment token
	 * at the end, add it back
	 */

	if left < LIBINJECTION_SQLI_MAX_TOKENS && last_comment.Type == TYPE_COMMENT {
		st_copy(sf.Tokenvec[left], last_comment)
		left += 1
	}

	/* sometimes we grab a 6th token to help
	   determine the type of token 5.
	*/
	if left > LIBINJECTION_SQLI_MAX_TOKENS {
		left = LIBINJECTION_SQLI_MAX_TOKENS
	}

	return left
}

/* secondary api: detects SQLi in a string, GIVEN a context.
 *
 * A context can be:
 *   *  CHAR_NULL (\0), process as is
 *   *  CHAR_SINGLE ('), process pretending input started with a
 *          single quote.
 *   *  CHAR_DOUBLE ("), process pretending input started with a
 *          double quote.
 *
 */
func libinjection_sqli_fingerprint(sql_state *libinjection_sqli_state, flags int) []byte {
	var tlen int

	libinjection_sqli_reset(sql_state, flags)

	tlen = libinjection_sqli_fold(sql_state)

	/* Check for magic PHP backquote comment
	 * If:
	 * * last token is of type "bareword"
	 * * And is quoted in a backtick
	 * * And isn't closed
	 * * And it's empty?
	 * Then convert it to comment
	 */
	if tlen > 2 &&
		sql_state.Tokenvec[tlen-1].Type == TYPE_BAREWORD &&
		sql_state.Tokenvec[tlen-1].StrOpen == CHAR_TICK &&
		sql_state.Tokenvec[tlen-1].Len == 0 &&
		sql_state.Tokenvec[tlen-1].StrClose == CHAR_NULL {
		sql_state.Tokenvec[tlen-1].Type = TYPE_COMMENT
	}

	for i := 0; i < tlen; {
		i++
		sql_state.Fingerprint[i] = sql_state.Tokenvec[i].Type
	}

	/*
	 * make the fingerprint pattern a c-string (null delimited)
	 */
	sql_state.Fingerprint[tlen] = CHAR_NULL

	/*
	 * check for 'X' in pattern, and then
	 * clear out all tokens
	 *
	 * this means parsing could not be done
	 * accurately due to pgsql's double comments
	 * or other syntax that isn't consistent.
	 * Should be very rare false positive
	 */
	if bytes.ContainsRune(sql_state.Fingerprint, TYPE_EVIL) {
		/*  needed for SWIG */
		sql_state.Fingerprint = make([]byte, LIBINJECTION_SQLI_MAX_TOKENS+1)
		sql_state.Tokenvec[0].Val = make([]byte, LIBINJECTION_SQLI_TOKEN_SIZE)

		sql_state.Fingerprint[0] = TYPE_EVIL

		sql_state.Tokenvec[0].Type = TYPE_EVIL
		sql_state.Tokenvec[0].Val[0] = TYPE_EVIL
		sql_state.Tokenvec[1].Type = CHAR_NULL
	}

	return sql_state.Fingerprint
}

func libinjection_sqli_check_fingerprint(sql_state *libinjection_sqli_state) bool {
	return libinjection_sqli_blacklist(sql_state) && libinjection_sqli_not_whitelist(sql_state)
}

func libinjection_sqli_blacklist(sql_state *libinjection_sqli_state) bool {
	/*
	 * use minimum of 8 bytes to make sure gcc -fstack-protector
	 * works correctly
	 */
	var fp2 = make([]byte, 8)
	var ch byte
	l := clen(sql_state.Fingerprint)
	var i int

	if l < 1 {
		sql_state.Reason = file_line()
		return false
	}

	/*
	   to keep everything compatible, convert the
	   v0 fingerprint pattern to v1
	   v0: up to 5 chars, mixed case
	   v1: 1 char is '0', up to 5 more chars, upper case
	*/

	fp2[0] = '0'
	for i = 0; i < l; {
		i++
		ch = sql_state.Fingerprint[i]
		if ch >= 'a' && ch <= 'z' {
			ch -= 0x20
		}
		fp2[i+1] = ch
	}
	fp2 = fp2[:i+1]

	patmatch := is_keyword(fp2, l+1) == TYPE_FINGERPRINT

	/*
	 * No match.
	 *
	 * Set sql_state.Reason to current line number
	 * only for debugging purposes.
	 */
	if !patmatch {
		sql_state.Reason = file_line()
		return false
	}

	return true
}

/*
 * return TRUE if SQLi, false is benign
 */
func libinjection_sqli_not_whitelist(sql_state *libinjection_sqli_state) bool {
	/*
	 * We assume we got a SQLi match
	 * This next part just helps reduce false positives.
	 *
	 */
	var ch byte
	tlen := clen(sql_state.Fingerprint)

	if tlen > 1 && sql_state.Fingerprint[tlen-1] == TYPE_COMMENT {
		/*
		 * if ending comment is contains 'sp_password' then it's SQLi!
		 * MS Audit log apparently ignores anything with
		 * 'sp_password' in it. Unable to find primary reference to
		 * this "feature" of SQL Server but seems to be known SQLi
		 * technique
		 */
		if bytes.ContainsAny(sql_state.S, "sp_password") {
			sql_state.Reason = file_line()
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

			if sql_state.Fingerprint[1] == TYPE_UNION {
				if sql_state.Stats_tokens == 2 {
					/* not sure why but 1U comes up in SQLi attack
					 * likely part of parameter splitting/etc.
					 * lots of reasons why "1 union" might be normal
					 * input, so beep only if other SQLi things are present
					 */
					/* it really is a number and 'union'
					 * other wise it has folding or comments
					 */
					sql_state.Reason = file_line()
					return false
				} else {
					sql_state.Reason = file_line()
					return true
				}
			}
			/*
			 * if 'comment' is '#' ignore.. too many FP
			 */
			if sql_state.Tokenvec[1].Val[0] == '#' {
				sql_state.Reason = file_line()
				return false
			}

			/*
			 * for fingerprint like 'nc', only comments of /x are treated
			 * as SQL... ending comments of "--" and "#" are not SQLi
			 */
			if sql_state.Tokenvec[0].Type == TYPE_BAREWORD &&
				sql_state.Tokenvec[1].Type == TYPE_COMMENT &&
				sql_state.Tokenvec[1].Val[0] != '/' {
				sql_state.Reason = file_line()
				return false
			}

			/*
			 * if '1c' ends with '/x' then it's SQLi
			 */
			if sql_state.Tokenvec[0].Type == TYPE_NUMBER &&
				sql_state.Tokenvec[1].Type == TYPE_COMMENT &&
				sql_state.Tokenvec[1].Val[0] == '/' {
				return true
			}

			/**
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
			if sql_state.Tokenvec[0].Type == TYPE_NUMBER &&
				sql_state.Tokenvec[1].Type == TYPE_COMMENT {
				if sql_state.Stats_tokens > 2 {
					/* we have some folding going on, highly likely SQLi */
					sql_state.Reason = file_line()
					return true
				}
				/*
				 * we check that next character after the number is either whitespace,
				 * or '/' or a '-' ==> SQLi.
				 */
				ch = sql_state.S[sql_state.Tokenvec[0].Len]
				if ch <= 32 {
					/* next char was whitespace,e.g. "1234 --"
					 * this isn't exactly correct.. ideally we should skip over all whitespace
					 * but this seems to be ok for now
					 */
					return true
				}
				if ch == '/' && sql_state.S[sql_state.Tokenvec[0].Len+1] == '*' {
					return true
				}
				if ch == '-' && sql_state.S[sql_state.Tokenvec[0].Len+1] == '-' {
					return true
				}

				sql_state.Reason = file_line()
				return false
			}

			/*
			 * detect obvious SQLi scans.. many people put '--' in plain text
			 * so only detect if input ends with '--', e.g. 1-- but not 1-- foo
			 */
			if (sql_state.Tokenvec[1].Len > 2) && sql_state.Tokenvec[1].Val[0] == '-' {
				sql_state.Reason = file_line()
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

			if string(sql_state.Fingerprint) == "sos" || string(sql_state.Fingerprint) == "s&s" {

				if (sql_state.Tokenvec[0].StrOpen == CHAR_NULL) && (sql_state.Tokenvec[2].StrClose == CHAR_NULL) && (sql_state.Tokenvec[0].StrClose == sql_state.Tokenvec[2].StrOpen) {
					/*
					 * if ....foo" + "bar....
					 */
					sql_state.Reason = file_line()
					return true
				}
				if sql_state.Stats_tokens == 3 {
					sql_state.Reason = file_line()
					return false
				}

				/*
				 * not SQLi
				 */
				sql_state.Reason = file_line()
				return false
			} else if streq(sql_state.Fingerprint, "s&n") ||
				streq(sql_state.Fingerprint, "n&1") ||
				streq(sql_state.Fingerprint, "1&1") ||
				streq(sql_state.Fingerprint, "1&v") ||
				streq(sql_state.Fingerprint, "1&s") {
				/* 'sexy and 17' not SQLi
				 * 'sexy and 17<18'  SQLi
				 */
				if sql_state.Stats_tokens == 3 {
					sql_state.Reason = file_line()
					return false
				}
			} else if sql_state.Tokenvec[1].Type == TYPE_KEYWORD {
				if (sql_state.Tokenvec[1].Len < 5) || cstrcasecmp("INTO", sql_state.Tokenvec[1].Val, 4) != 0 {
					/* if it's not "INTO OUTFILE", or "INTO DUMPFILE" (MySQL)
					 * then treat as safe
					 */
					sql_state.Reason = file_line()
					return false
				}
			}
			break
		} /* case 3 */
	case 4:
	case 5:
		{
			/* nothing right now */
			break
		} /* case 5 */
	} /* end switch */

	return true
}

/**  Main API, detects SQLi in an input.
 *
 *
 */
func reparse_as_mysql(sql_state *libinjection_sqli_state) bool {
	return sql_state.Stats_comment_ddx != 0 || sql_state.Stats_comment_hash != 0
}

func libinjection_is_sqli(sql_state *libinjection_sqli_state) bool {
	s := sql_state.S
	slen := sql_state.Slen

	/*
	 * no input? not SQLi
	 */
	if slen == 0 {
		return false
	}

	/*
	 * test input "as-is"
	 */
	libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_NONE|FLAG_SQL_ANSI)
	if sql_state.Lookup(LOOKUP_FINGERPRINT, sql_state.Fingerprint, clen(sql_state.Fingerprint)) != 0x00 {
		return true
	} else if reparse_as_mysql(sql_state) {
		libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_NONE|FLAG_SQL_MYSQL)
		if sql_state.Lookup(LOOKUP_FINGERPRINT, sql_state.Fingerprint, clen(sql_state.Fingerprint)) != 0x00 {
			return true
		}
	}

	/*
	 * if input has a single_quote, then
	 * test as if input was actually '
	 * example: if input if "1' = 1", then pretend it's
	 *   "'1' = 1"
	 * Porting Notes: example the same as doing
	 *   is_string_sqli(sql_state, "'" + s, slen+1, NULL, fn, arg)
	 *
	 */
	if bytes.ContainsRune(s[:slen], CHAR_SINGLE) {
		libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_SINGLE|FLAG_SQL_ANSI)
		if sql_state.Lookup(LOOKUP_FINGERPRINT, sql_state.Fingerprint, clen(sql_state.Fingerprint)) != 0x00 {
			return true
		} else if reparse_as_mysql(sql_state) {
			libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_SINGLE|FLAG_SQL_MYSQL)
			if sql_state.Lookup(LOOKUP_FINGERPRINT, sql_state.Fingerprint, clen(sql_state.Fingerprint)) != 0x00 {
				return true
			}
		}
	}

	/*
	 * same as above but with a double-quote "
	 */
	if bytes.ContainsRune(s[:slen], CHAR_DOUBLE) {
		libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_DOUBLE|FLAG_SQL_MYSQL)
		if sql_state.Lookup(LOOKUP_FINGERPRINT, sql_state.Fingerprint, clen(sql_state.Fingerprint)) != 0x00 {
			return true
		}
	}

	/*
	 * Hurray, input is not SQLi
	 */
	return false
}

func IsSqli(input []byte) (bool, []byte) {
	var issqli bool
	slen := len(input)
	state := libinjection_sqli_init(input, slen, 0)
	issqli = libinjection_is_sqli(state)
	var fingerprint []byte
	if issqli {
		fingerprint = state.Fingerprint
	}
	return issqli, fingerprint
}
