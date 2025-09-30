package handlers

import (
    "net/http"
)


// adapter: func() into http.Flusher
type flusherFunc func()
func (f flusherFunc) Flush() { f() }
// wrappers or falls back to ResponseController
type unwrapper interface{ Unwrap() http.ResponseWriter }

func GetFlusher(w http.ResponseWriter) (http.Flusher, bool) {
    // direct
    if f, ok := w.(http.Flusher); ok {
        return f, true
    }
    // unwrap chain
    cur := w
    for {
        uw, ok := cur.(unwrapper)
        if !ok {
            break
        }
        cur = uw.Unwrap()
        if f, ok := cur.(http.Flusher); ok {
            return f, true
        }
    }
// Go 1.20+: ResponseController can Flush even if Flusher isn’t implemented
    rc := http.NewResponseController(w)
    if rc != nil {
	    return flusherFunc(func() { _ = rc.Flush() }), true
   }
    return nil, false
}
