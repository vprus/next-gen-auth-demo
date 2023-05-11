package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"reflect"
)

// Look at the response with new credentials, and see if those credentials, in turns
// are signed by the authenticator itself.
//
// There are three parts to it
// - whether the credential id and public key are signed at all, or just provided to us
// - whether they are signed by authenticator's key, or by the private key of the credential
// - whether we can verify authenticator key in some way.
func verifyAttestationsResponse(response *protocol.ParsedCredentialCreationData) string {
	serializedClientData := response.Raw.AttestationResponse.ClientDataJSON
	authData := response.Response.AttestationObject.RawAuthData
	attStmt := response.Response.AttestationObject.AttStatement

	// No signature. We can store id and public key, but no idea what produced them
	if attStmt == nil || len(attStmt) == 0 {
		return "OK, authenticator is unknown"
	}
	// We have some signature
	signature := attStmt["sig"].([]byte)

	if x5c, ok := attStmt["x5c"]; ok {
		// When the x5c field is present, it means that signature is made by authenticator's
		// private key. First element of x5c contains the matching certificate, with a public
		// key.

		cert, err := x509.ParseCertificate(x5c.([]interface{})[0].([]byte))
		if err != nil {
			return "OK, authenticator certificate is unparseable"
		}

		// See if we validate authenticator certificate. For now,
		// we only support validation using YubiKey root CA.
		var certificateStatus = "not validated"

		uuidObj, _ := uuid.FromBytes(response.Response.AttestationObject.AuthData.AttData.AAGUID)
		var rootPEM []byte
		if rootCertificates == nil {
			prepareRootCertificates()
		}
		if root, ok := rootCertificates[uuidObj.String()]; ok {
			log.Info().Msgf("found root certificate for %v in official blob", uuidObj)
			rootPEM = []byte(root)
		} else {
			// Try YubiKey root
			rootPEM, err = os.ReadFile("yubico-u2f-ca-certs.txt")
			if err != nil {
				log.Info().Err(err).Msg("cannot read root certificate")
			}
			log.Info().Msgf("using root certificate for YubiKey")
		}

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(rootPEM)
		if !ok {
			log.Error().Msg("cannot append root certificate")
		}

		opts := x509.VerifyOptions{
			Roots: roots,
		}
		if _, err := cert.Verify(opts); err != nil {
			log.Info().Err(err).Msg("cannot verify certificate")
		} else {
			certificateStatus = "validated via root CA"
		}

		if cert.PublicKeyAlgorithm.String() == "ECDSA" {
			publicKey := cert.PublicKey.(*ecdsa.PublicKey)

			hasher := crypto.SHA256.New()
			clientDataHash := sha256.Sum256(serializedClientData)
			sigData := append(authData, clientDataHash[:]...)
			hasher.Write(sigData)

			r := ecdsa.VerifyASN1(publicKey, hasher.Sum(nil), signature)
			if !r {
				return "Signature verification failed"
			}
		} else {
			return fmt.Sprintf("Unsupported signature algorithm %v", cert.PublicKeyAlgorithm)
		}

		return fmt.Sprintf("OK, credential signed by %s, %s", cert.Subject.CommonName, certificateStatus)
	} else {
		// We have attStmt, but no certificates in it. In this case, the data is signed by
		// the credential private key. It does not really prove anything, other than the
		// fact that the other wise can sign.

		publicKey := response.Response.AttestationObject.AuthData.AttData.CredentialPublicKey

		clientDataHash := sha256.Sum256(serializedClientData)
		sigData := append(authData, clientDataHash[:]...)
		key, err := webauthncose.ParsePublicKey(publicKey)
		if err != nil {
			log.Err(err).Msg("cannot parse public key")
		}

		valid, err := webauthncose.VerifySignature(key, sigData, signature)
		if err != nil {
			log.Err(err).Msg("error verifying signature")
		}
		if !valid {
			log.Info().Msg("signature is not valid")
		}
		return "OK, credential is self-signed"
	}
}

// Verify that attestation response indeed contains a valid signature of challange
// using credential private key. We use public key stored in the server for the check.
//
// Important: the webauthn library already does that check, and many others. We repeat
// it here only for illustration. Don't even think about reusing this in production.
func verifyAssertionResponse(response *protocol.ParsedCredentialAssertionData, publicKey []byte) string {
	serializedClientData := response.Raw.AssertionResponse.ClientDataJSON
	authData := response.Raw.AssertionResponse.AuthenticatorData
	//signature, _ := base64.RawURLEncoding.DecodeString(string(response.Raw.AssertionResponse.Signature))

	clientDataHash := sha256.Sum256(serializedClientData)
	signedData := append(authData, clientDataHash[:]...)
	key, err := webauthncose.ParsePublicKey(publicKey)
	if err != nil {
		log.Err(err).Msg("cannot parse public key")
		return "cannot parse public key"
	}

	valid, err := webauthncose.VerifySignature(key, signedData, response.Response.Signature)
	if err != nil {
		log.Err(err).Msg("error verifying signature")
		return "could not verify signature"
	}
	if !valid {
		log.Info().Msg("signature is not valid")
		return "signature is not valid"
	}
	return "signature is valid"
}

// The response that JS gets from the navigator.credentials.create call is
// a weird mix of UTF8 encoded JSON, a binary format called CBOR, and
// totally custom binary formats.
//
// This function converts it into a hierarchical tree of the actual data
// that can be shown as JSON.
func explainAttestationResponse(reader io.Reader) map[string]interface{} {
	empty := map[string]interface{}{
		"error": "could not decode the data",
	}
	m := make(map[string]interface{})
	if err := json.NewDecoder(reader).Decode(&m); err != nil {
		log.Err(err).Msg("cannot decode top-level response")
		return empty
	}
	response := m["response"].(map[string]interface{})

	if cd, ok := response["clientDataJSON"]; ok {
		// This field is base64 encoding of JSON
		clientDataBytes, _ := base64.RawURLEncoding.DecodeString(cd.(string))
		cdm := make(map[string]interface{})
		json.NewDecoder(bytes.NewReader(clientDataBytes)).Decode(&cdm)
		response["clientDataJSON"] = cdm
	}

	if ao, ok := response["attestationObject"]; ok {
		// This field is base64 encoding of binary serialization format called CBOR
		content, _ := base64.RawURLEncoding.DecodeString(ao.(string))
		aom := make(map[string]interface{})
		decMode, _ := cbor.DecOptions{
			DefaultMapType: reflect.MapOf(reflect.TypeOf(""), reflect.TypeOf((*interface{})(nil)).Elem()),
		}.DecMode()
		err := decMode.Unmarshal(content, &aom)
		if err != nil {
			log.Err(err).Msg("cannot unmarshal attestationObject")
			return empty
		}

		// This one is a nested binary format, and we'll use the webauthn library to
		// unpack it for us.
		authDataContent := aom["authData"].([]byte)
		ad := &protocol.AuthenticatorData{}
		if err := ad.Unmarshal(authDataContent); err == nil {
			// Now convert AuthenticatorData to map, so that we can make more changes
			adJsonBytes, _ := json.Marshal(ad)
			adm := make(map[string]interface{})
			json.Unmarshal(adJsonBytes, &adm)
			aom["authData"] = adm
			// Convert authenticator GUID from binary to string
			attData := adm["att_data"].(map[string]interface{})
			aaguid_base64 := attData["aaguid"].(string)
			aaguid_bytes, _ := base64.StdEncoding.DecodeString(aaguid_base64)
			aaguid, _ := uuid.FromBytes(aaguid_bytes)
			attData["aaguid"] = aaguid.String()
		} else {
			log.Err(err).Msg("Could not decode auth data")
			return empty
		}

		response["attestationObject"] = aom
	}

	return response
}

// Just like for attestation response, this function renders assertion
// response in a more readable fashion.
func explainAssertionResponse(reader io.Reader) map[string]interface{} {
	empty := map[string]interface{}{
		"error": "could not decode the data",
	}
	m := make(map[string]interface{})
	if err := json.NewDecoder(reader).Decode(&m); err != nil {
		log.Err(err).Msg("cannot decode top-level response")
		return empty
	}
	response := m["response"].(map[string]interface{})

	clientDataBytes, _ := base64.RawURLEncoding.DecodeString(response["clientDataJSON"].(string))
	cdm := make(map[string]interface{})
	json.NewDecoder(bytes.NewReader(clientDataBytes)).Decode(&cdm)
	response["clientDataJSON"] = cdm

	authDataContent, _ := base64.RawURLEncoding.DecodeString(response["authenticatorData"].(string))
	ad := &protocol.AuthenticatorData{}
	if err := ad.Unmarshal(authDataContent); err == nil {
		response["authenticatorData"] = ad
	} else {
		log.Err(err).Msg("Could not decode auth data")
		return empty
	}

	return response
}

// Map from AAGUID to PEM string for root certificate
var rootCertificates map[string]string

// There is an official binary blob containing root certificates for various authenticators
// This function parses it and stores authenticator ids and root certificates.
//
// As the earlier functions, this code should not be used for production purposes.
func prepareRootCertificates() {
	rootCertificates = make(map[string]string)

	jwtParser := jwt.NewParser()
	// Downloaded from https://mds3.fidoalliance.org/
	// See https://fidoalliance.org/metadata/#:~:text=For%20assistance%20on%20the%20FIDO,%40mymds.fidoalliance.org.
	blogBytes, _ := os.ReadFile("blob.jwt")
	token, _, err := jwtParser.ParseUnverified(string(blogBytes), jwt.MapClaims{})
	if err != nil {
		log.Err(err).Msg("cannot parse metadata TOC")
		return
	}
	entries := token.Claims.(jwt.MapClaims)["entries"].([]interface{})

	for _, e := range entries {
		em := e.(map[string]interface{})
		if guid, ok := em["aaguid"]; ok {
			if metadataStatement_ := em["metadataStatement"]; ok {
				metadataStatement := metadataStatement_.(map[string]interface{})
				if roots_, ok := metadataStatement["attestationRootCertificates"]; ok {
					roots := roots_.([]interface{})
					if len(roots) > 0 {
						firstRootString := roots[0].(string)
						// Add PEM envelope, since crypto.x509 cannot parse just the raw data.
						rootCertificates[guid.(string)] = "-----BEGIN CERTIFICATE-----\n" + firstRootString +
							"\n-----END CERTIFICATE-----\n"
					}
				}
			}
		}
	}
}
