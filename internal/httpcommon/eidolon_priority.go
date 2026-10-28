package httpcommon

import (
	"context"
	"strings"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// PriorityField returns the value of the priority field (RFC 9218) a
// request sends, its lines joined by ", ": among the exact fields in exact
// mode, which replace h, otherwise in h. It is "" without one.
func PriorityField(ctx context.Context, h map[string][]string) string {
	var vv []string
	if exact := order.ExactFromContext(ctx); exact != nil {
		for _, f := range exact {
			if strings.EqualFold(f.Name, "priority") {
				vv = append(vv, f.Value)
			}
		}
	} else {
		for k, v := range h {
			if strings.EqualFold(k, "priority") {
				vv = append(vv, v...)
			}
		}
	}
	return strings.Join(vv, ", ")
}
