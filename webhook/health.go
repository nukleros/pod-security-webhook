// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package webhook

import (
	"fmt"
	"net/http"
)

const statusOkMessage = `{"msg": "server is healthy"}`

// healthCheck implements a simple health check that returns a 200 ok response.
func (webhook *Webhook) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, err := fmt.Fprint(w, statusOkMessage)
	if err != nil {
		webhook.Log.ErrorF("%s - error writing response", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	webhook.Log.Debug(statusOkMessage)
	w.WriteHeader(http.StatusOK)
}
