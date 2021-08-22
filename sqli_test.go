package libinjection

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
)

func csprintf(buf *[]byte, from int, format string, data ...interface{}) int {
	res := fmt.Sprintf(format, data...)
	lres := len(res)
	for i := range res {
		sum := i + from
		if sum >= len(*buf) {
			*buf = append(*buf, res[i])
		} else {
			(*buf)[i+from] = res[i]
		}
	}
	return lres
}

func print_string(buf []byte, l int, t *stoken_t) ([]byte, int) {
	slen := 0

	/* print opening quote */
	if t.StrOpen != '\x00' {
		buf[l] = t.StrOpen
		slen = 1
		l += slen
	}

	/* print content */
	s := fmt.Sprintf("%s ", t.Val)
	slen = clen([]byte(s))
	for i := range s {
		if l+i >= len(buf) {
			buf = append(buf, s[i])
		} else {
			buf[l+i] = s[i]
		}
	}
	l += slen

	/* print closing quote */
	if t.StrClose != '\x00' {
		slen = 1
		buf[l] = t.StrClose
		l += slen
	}

	return buf, l
}

func print_var(buf []byte, l int, t *stoken_t) ([]byte, int) {
	slen := 0
	if t.Count >= 1 {
		slen = 1
		buf[l] = '@'
		l += slen
	}
	if t.Count == 2 {
		slen = 1
		buf[l] = '@'
		l += slen
	}
	return print_string(buf, l, t)
}

func print_token(buf []byte, l int, t *stoken_t) ([]byte, int) {
	slen := 0
	slen = csprintf(&buf, l, "%c ", t.Type)
	l += slen
	switch t.Type {
	case 's':
		buf, l = print_string(buf, l, t)
	case 'v':
		buf, l = print_var(buf, l, t)
	default:
		slen = csprintf(&buf, l, "%s", t.Val)
		l += slen
	}
	slen = csprintf(&buf, l, "%c", t.Type)
	l += slen
	return buf, l
}

func TestCsprintf(t *testing.T) {
	str := []byte("some test")
	csprintf(&str, 3, "%s", "supertest")
	if string(str) != "somsupertest" {
		t.Error("csprintf failed with " + string(str))
	}

}

func TestEngine(t *testing.T) {
	dirs, err := os.ReadDir("./tests")
	if err != nil {
		t.Error(err)
	}
	for _, dir := range dirs {
		fn := dir.Name()
		if !strings.HasSuffix(fn, ".txt") {
			continue
		}
		spl := strings.Split(fn, "-")
		tp := spl[1]
		data, err := os.Open(path.Join("./tests", fn))
		if err != nil {
			t.Error(err)
		}
		scanner := bufio.NewScanner(data)
		tname := ""
		tinput := ""
		texpect := []string{}
		for scanner.Scan() {
			l := scanner.Text()
			if l == "--TEST--" {
				scanner.Scan()
				tname = scanner.Text()
			} else if l == "--INPUT--" {
				scanner.Scan()
				tinput = scanner.Text()
			} else if l == "--EXPECTED--" {
				for scanner.Scan() {
					texpect = append(texpect, scanner.Text())
				}
			}
		}
		g_actual := []byte{}
		slen := 0
		flags := 0
		fmt.Printf("%s (%s): %s\n", fn, tname, tinput)
		switch tp {
		case "tokens":
			sf := NewSqli([]byte(tinput), len(tinput), FLAG_QUOTE_NONE|FLAG_SQL_ANSI)
			for sf.Tokenize() {
				g_actual, slen = print_token(g_actual, 0, sf.Current)
				fmt.Println(string(g_actual))
			}
		case "folding":
			flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI
		case "sqli":
			flags = FLAG_NONE
		case "xss":
			flags = FLAG_NONE
		case "html5":
			//not implemented
		default:
			t.Error("invalid test type " + fn)
		}
		flags = flags
		slen = slen
		tname = tname
		fmt.Printf("%s\n", g_actual)
	}
}
