package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/rs/zerolog/log"

	"bytes"
	"io"
	"net/http"
)

type FakeUser struct {
	credentials []webauthn.Credential
}

func (u *FakeUser) WebAuthnID() []byte {
	return []byte("id1")
}

func (u *FakeUser) WebAuthnName() string {
	return "Joe Black"
}

func (u *FakeUser) WebAuthnDisplayName() string {
	return "Joe Black"
}

func (u *FakeUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *FakeUser) WebAuthnIcon() string {
	return ""
}

func main() {
	wconfig := &webauthn.Config{
		RPDisplayName: "Next Gen Auth Demo",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000"},

		AttestationPreference: "direct",
	}

	var wa *webauthn.WebAuthn
	var err error

	if wa, err = webauthn.New(wconfig); err != nil {
		log.Fatal().Err(err).Msg("cannot initialize webauthn library")
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	fileServer := http.FileServer(http.Dir("static/"))

	fakeUser := &FakeUser{}
	var fakeSession *webauthn.SessionData
	var credential *webauthn.Credential

	r.Post("/api/enroll/start", func(writer http.ResponseWriter, request *http.Request) {
		attachment := request.URL.Query().Get("attachment")
		if len(attachment) == 0 {
			attachment = "platform"
		}
		var options *protocol.CredentialCreation
		s := protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.AuthenticatorAttachment(attachment),
		}
		options, fakeSession, err = wa.BeginRegistration(fakeUser, webauthn.WithAuthenticatorSelection(s))
		if err != nil {
			log.Fatal().Err(err).Msg("cannot begin registration")
			render.Status(request, http.StatusInternalServerError)
			return
		}
		render.JSON(writer, request, options)
	})

	r.Post("/api/enroll/finish", func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)

		response, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
		if err != nil {
			log.Err(err).Msgf("could not parse credentials response: %v", err.(*protocol.Error).DevInfo)
			return
		}

		credential, err = wa.CreateCredential(fakeUser, *fakeSession, response)
		if err != nil {
			log.Err(err).Msgf("could not finished creating credentials: %v", err.(*protocol.Error).DevInfo)
			return
		}

		log.Info().Msgf("Authenticator: %v", credential.Authenticator)

		fakeUser.credentials = []webauthn.Credential{*credential}
		log.Info().Msgf("user has %v credentials now", len(fakeUser.WebAuthnCredentials()))
		render.JSON(writer, request, map[string]interface{}{
			"status":      verifyAttestationsResponse(response),
			"explanation": explainAttestationResponse(bytes.NewReader(body)),
		})
	})

	r.Post("/api/login/start", func(writer http.ResponseWriter, request *http.Request) {
		var options *protocol.CredentialAssertion
		log.Info().Msgf("trying login, user has %v credentials now", len(fakeUser.WebAuthnCredentials()))
		options, fakeSession, err = wa.BeginLogin(fakeUser)
		if err != nil {
			log.Err(err).Msg("could not start login")
			// Handle Error and return.
			return
		}
		render.JSON(writer, request, options)
	})

	r.Post("/api/login/finish", func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)

		response, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
		if err != nil {
			// Handle Error and return.

			return
		}

		_, err = wa.ValidateLogin(fakeUser, *fakeSession, response)
		if err != nil {
			// Handle Error and return.

			return
		}

		render.JSON(writer, request, map[string]interface{}{
			"status":      verifyAssertionResponse(response, fakeUser.credentials[0].PublicKey),
			"explanation": explainAssertionResponse(bytes.NewReader(body)),
		})
	})

	r.Get("/*", fileServer.ServeHTTP)

	http.ListenAndServe(":3000", r)
}
