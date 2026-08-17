package main

import (
	"context"
	"time"

	"github.com/qarven/oryon-go/internal/app"
)

// @title           Oryon API
// @version         1.0
// @description     Oryon provides authentication, authorization and profile management APIs.
// @termsOfService  https://oryon.com/terms
// @contact.name    Contact Support
// @contact.url     https://oryon.com/contact
// @contact.email   support@oryon.com
// @license.name    MIT
// @license.url     https://mit-license.org/
// @server          http://localhost:8000
// @server          https://localhost:8000
// @securityDefinitions.apikey  BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT.
func main() {
	application := app.New()    // Initialize the application
	wait := application.Start() // Start the application and wait for the termination signal
	<-wait                      // Wait for the application to receive a termination signal

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	application.Stop(ctx) // Stop the application gracefully
}
