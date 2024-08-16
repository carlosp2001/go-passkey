package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn *webauthn.WebAuthn
	err      error

	datastore PasskeyStore
	//sessions  SessionStore
	l Logger
)

type Logger interface {
	Printf(format string, v ...interface{})
}

type PasskeyUser interface {
	webauthn.User
	AddCredential(*webauthn.Credential)
	UpdateCredential(*webauthn.Credential)
}

type PasskeyStore interface {
	GetOrCreateUser(userName string) PasskeyUser
	SaveUser(PasskeyUser)
	GenSessionID() (string, error)
	GetSession(token string) (webauthn.SessionData, bool)
	SaveSession(token string, data webauthn.SessionData)
	DeleteSession(token string)
}

func main() {
	l = log.Default()

	proto := getEnv("PROTO", "https")
	tepago := getEnv("HOST", "localhost")
	port := getEnv("PORT", "8080")
	origin := fmt.Sprintf("%s://%s:%s", proto, tepago, port)

	l.Printf("[INFO] make webauthn config")
	wconfig := &webauthn.Config{
		RPDisplayName: "naya",           // Display Name for your site
		RPID:          tepago,           // Generally the FQDN for your site
		RPOrigins:     []string{origin}, // The origin URLs allowed for WebAuthn
	}

	l.Printf("[INFO] create webauthn")
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	l.Printf("[INFO] create datastore")
	datastore = NewInMem(l)

	l.Printf("[INFO] register routes")
	// Serve the web files
	http.Handle("/", http.FileServer(http.Dir("./web")))

	// Add auth the routes
	http.HandleFunc("/api/passkey/registerStart", BeginRegistration)
	http.HandleFunc("/api/passkey/registerFinish", FinishRegistration)
	http.HandleFunc("/api/passkey/loginStart", BeginLogin)
	http.HandleFunc("/api/passkey/loginFinish", FinishLogin)
	http.HandleFunc("/.well-known/assetlinks.json", ServeJsonFile)

	http.Handle("/private", LoggedInMiddleware(http.HandlerFunc(PrivatePage)))

	// Start the server with HTTPS
	l.Printf("[INFO] start server at %s", origin)
	//if err := http.ListenAndServeTLS(port, "server.crt", "server.key", nil); err != nil {
	//	fmt.Println(err)
	//}
	if err := http.ListenAndServeTLS(tepago+":"+port, "server.crt", "server.key", nil); err != nil {
		fmt.Println(err)
	}
}

func ServeJsonFile(writer http.ResponseWriter, request *http.Request) {
	file, err := os.Open("assetlinks.json")
	if err != nil {
		http.Error(writer, "Error al abrir el archivo", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Lee el contenido del archivo
	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(writer, "Error al leer el archivo", http.StatusInternalServerError)
		return
	}

	// Establece el tipo de contenido a JSON
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)

	// Escribe el contenido del archivo en la respuesta
	writer.Write(content)
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	l.Printf("[INFO] begin registration ----------------------\\")

	username, err := getUsername(r)
	if err != nil {
		l.Printf("[ERRO] can't get user name: %s", err.Error())
		panic(err)
	}

	user := datastore.GetOrCreateUser(username)

	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin registration: %s", err.Error())
		l.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	t, err := datastore.GenSessionID()
	if err != nil {
		l.Printf("[ERRO] can't generate session id: %s", err.Error())
		panic(err)
	}

	datastore.SaveSession(t, *session)

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    t,
		Path:     "api/passkey/registerStart",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	JSONResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie("sid")
	if err != nil {
		l.Printf("[ERRO] can't get session id: %s", err.Error())
		panic(err)
	}

	session, _ := datastore.GetSession(sid.Value)

	user := datastore.GetOrCreateUser(string(session.UserID))

	credential, err := webAuthn.FinishRegistration(user, session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		l.Printf("[ERRO] %s", msg)
		http.SetCookie(w, &http.Cookie{
			Name:  "sid",
			Value: "",
		})
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	user.AddCredential(credential)
	datastore.SaveUser(user)
	datastore.DeleteSession(sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:  "sid",
		Value: "",
	})

	l.Printf("[INFO] finish registration ----------------------/")
	JSONResponse(w, "Registration Success", http.StatusOK)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	l.Printf("[INFO] begin login ----------------------\\")

	username, err := getUsername(r)
	if err != nil {
		l.Printf("[ERRO] can't get user name: %s", err.Error())
		panic(err)
	}

	user := datastore.GetOrCreateUser(username)

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		l.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	t, err := datastore.GenSessionID()
	if err != nil {
		l.Printf("[ERRO] can't generate session id: %s", err.Error())
		panic(err)
	}
	datastore.SaveSession(t, *session)

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    t,
		Path:     "api/passkey/loginStart",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	JSONResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie("sid")
	if err != nil {
		l.Printf("[ERRO] can't get session id: %s", err.Error())
		panic(err)
	}

	session, _ := datastore.GetSession(sid.Value)

	user := datastore.GetOrCreateUser(string(session.UserID))

	credential, err := webAuthn.FinishLogin(user, session, r)
	if err != nil {
		l.Printf("[ERRO] can't finish login: %s", err.Error())
		panic(err)
	}

	if credential.Authenticator.CloneWarning {
		l.Printf("[WARN] can't finish login: %s", "CloneWarning")
	}

	user.UpdateCredential(credential)
	datastore.SaveUser(user)

	datastore.DeleteSession(sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:  "sid",
		Value: "",
	})

	t, err := datastore.GenSessionID()
	if err != nil {
		l.Printf("[ERRO] can't generate session id: %s", err.Error())
		panic(err)
	}

	datastore.SaveSession(t, webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    t,
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	l.Printf("[INFO] finish login ----------------------/")
	JSONResponse(w, "Login Success", http.StatusOK)
}

func PrivatePage(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Hello, World!"))
}

func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func getUsername(r *http.Request) (string, error) {
	type Username struct {
		Username string `json:"username"`
	}
	var u Username
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return "", err
	}

	return u.Username, nil
}

func getEnv(key, def string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return def
}

func LoggedInMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie("sid")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		session, ok := datastore.GetSession(sid.Value)
		if !ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if session.Expires.Before(time.Now()) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
