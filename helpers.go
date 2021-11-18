package libinjection

import "strings"

func strlencspn(s string, unaccepted string) int {
	l := len(s)
	for i := 0; i < l; i++ {
		if strings.IndexByte(unaccepted, s[1]) != -1 {
			return i
		}
	}
	return len(s)
}

func strlenspn(s string, accept string) int {
	l := len(s)
	for i := 0; i < l; i++ {
		if strings.IndexByte(accept, s[i]) == -1 {
			return i
		}
	}
	return l
}

func flag2delim(flag int) byte {
	if (flag & FLAG_QUOTE_SINGLE) != 0 {
		return CHAR_SINGLE
	} else if (flag & FLAG_QUOTE_DOUBLE) != 0 {
		return CHAR_DOUBLE
	} else {
		return CHAR_NULL
	}
}

func is_double_delim_escaped(cur int, end int, s string) bool {
	return ((cur + 1) < end) && (s[cur+1] == s[cur])
}

/*
 * "  \"   " one backslash = escaped! " \\"   " two backslash = not escaped!
 * "\\\"   " three backslash = escaped!
 */
func is_backslash_escaped(end int, start int, s string) bool {
	i := end

	for i >= start {
		if s[i] != '\\' {
			break
		}
		i--
	}

	return ((end - i) & 1) == 1
}

/*
 * This detects MySQL comments, comments that start with /x! We just ban
 * these now but previously we attempted to parse the inside
 *
 * For reference: the form of /x![anything]x/ or /x!12345[anything] x/
 *
 * Mysql 3 (maybe 4), allowed this: /x!0selectx/ 1; where 0 could be any
 * number.
 *
 * The last version of MySQL 3 was in 2003. It is unclear if the MySQL 3
 * syntax was allowed in MySQL 4. The last version of MySQL 4 was in 2008
 *
 */
func is_mysql_comment(s string, l int, pos int) bool {
	/*
	 * so far... s.charAt(pos) == '/' && s.charAt(pos+1) == '*'
	 */

	if pos+2 >= l {
		/* not a mysql comment */
		return false
	}

	if s[pos+2] != '!' {
		/* not a mysql comment */
		return false
	}

	/*
	 * this is a mysql comment got "/x!"
	 */
	return true
}

func char_is_white(ch byte) bool {
	/*
	 * ' ' space is 0x20 '\t 0x09 \011 horizontal tab '\n' 0x0a \012 new
	 * line '\v' 0x0b \013 vertical tab '\f' 0x0c \014 new page '\r' 0x0d
	 * \015 carriage return 0x00 \000 null (oracle) 0xa0 \240 is Latin-1
	 */

	switch ch {
	case 0x20:
		return true
	case 0x09:
		return true
	case 0x0a:
		return true
	case 0x0b:
		return true
	case 0x0c:
		return true
	case 0x0d:
		return true
	case 0x00:
		return true
	case 0xa0:
		return true
	default:
		return false
	}
}
