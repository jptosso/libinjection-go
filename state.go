package libinjection

type State struct {
	s                  string /* input string */
	slen               int    /* length of input */
	fplen              int    /* length of fingerprint */
	flags              int    /* flag to indicate which mode we're running in: example.) flag_quote_none AND flag_sql_ansi */
	pos                int    /* index in string during tokenization */
	current            int    /* current position in tokenvec*/
	stats_comment_ddw  int
	stats_comment_ddx  int
	stats_comment_c    int /* c-style comments found  /x .. x/ */
	stats_comment_hash int /* '#' operators or MySQL EOL comments found */
	stats_folds        int
	stats_tokens       int
	tokenvec           [8]*Token
	fingerprint        string
}

func newState(s string, l int, flags int) *State {
	if flags == 0 {
		flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI
	}
	return &State{
		s:                 s,
		slen:              l,
		fplen:             0,
		flags:             flags,
		pos:               0,
		current:           0,
		stats_comment_ddw: 0,
	}
}
