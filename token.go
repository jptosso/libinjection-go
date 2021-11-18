package libinjection

import "strings"

type Token struct {
	Len       int
	Type      byte
	val       string
	pos       int
	count     int
	str_close byte
	str_open  byte
}

func (token *Token) is_arithmetic_op() bool {
	if token.Len == 1 && token.Type == TYPE_OPERATOR {
		ch := token.val[0]
		return (ch == '*' || ch == '/' || ch == '-' || ch == '+' || ch == '%')
	}
	return false
}

func (token *Token) is_unary_op() bool {
	str := token.val
	l := token.Len

	if token.Type != TYPE_OPERATOR {
		return false
	}

	switch l {
	case 1:
		return str[0] == '+' || str[0] == '-' || str[0] == '!' || str[0] == '~'
	case 2:
		return str[0] == '!' && str[1] == '!'
	case 3:
		return strings.EqualFold(str, "not")
	default:
		return false
	}
}

/*
 * See if two tokens can be merged since they are compound SQL phrases.
 *
 * This takes two tokens, and, if they are the right type, merges their
 * values together. Then checks to see if the new value is special using the
 * PHRASES mapping.
 *
 * Example: "UNION" + "ALL" ==> "UNION ALL"
 *
 * C Security Notes: this is safe to use C-strings (null-terminated) since
 * the types involved by definition do not have embedded nulls (e.g. there
 * is no keyword with embedded null)
 *
 * Porting Notes: since this is C, it's oddly complicated. This is just:
 * multikeywords[token.value + ' ' + token2.value]
 *
 */
func (a *Token) syntax_merge_words(sqli *Sqli, apos int, b *Token, bpos int) bool {
	merged := ""
	state := sqli.state
	var wordtype byte

	/* first token must not represent any of these types */
	if !(a.Type == TYPE_KEYWORD || a.Type == TYPE_BAREWORD || a.Type == TYPE_OPERATOR || a.Type == TYPE_UNION || a.Type == TYPE_FUNCTION || a.Type == TYPE_EXPRESSION || a.Type == TYPE_SQLTYPE) {
		return false
	}

	/* second token must not represent any of these types */
	if b.Type != TYPE_KEYWORD && b.Type != TYPE_BAREWORD && b.Type != TYPE_OPERATOR && b.Type != TYPE_SQLTYPE && b.Type != TYPE_LOGIC_OPERATOR && b.Type != TYPE_FUNCTION && b.Type != TYPE_UNION && b.Type != TYPE_EXPRESSION {
		return false
	}

	merged = a.val + " " + b.val
	wordtype = libinjection_sqli_lookup_word(merged)

	if wordtype != 0x00 {
		token := newToken(int(wordtype), a.pos, len(merged), merged)
		state.tokenvec[apos] = token
		/* shift down all tokens after b by one index */
		for i := bpos; i < len(state.tokenvec)-1; i++ {
			if state.tokenvec[i] != nil {
				state.tokenvec[i] = state.tokenvec[i+1]
			} else {
				break
			}
		}
		state.tokenvec[7] = nil
		return true
	} else {
		return false
	}

}

func newToken(stype int, pos int, l int, val string) *Token {
	return &Token{
		Type:      byte(stype),
		Len:       l,
		val:       val,
		pos:       pos,
		count:     0,
		str_close: 0,
		str_open:  0,
	}
}
