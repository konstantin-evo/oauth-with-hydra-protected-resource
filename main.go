package main

import (
	"clientCredentialsTest/model"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const hydraAdminURL = "http://localhost:4445/admin/oauth2/introspect"
const requiredScope = "read"

func main() {

	// Create a new Gin router
	// Define a route for the secured resource
	r := gin.Default()
	r.GET("/secured-resource", handleSecuredResource)

	// Get the port from the environment variable or use the default (8080)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Run the Gin application
	if err := r.Run(":" + port); err != nil {
		fmt.Println(err)
	}
}

// Function to handle the "/secured-resource" endpoint
func handleSecuredResource(c *gin.Context) {
	// Get the token from the request header
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Introspect the token using Hydra
	tokenInfo, err := introspectToken(token)
	if err != nil || !tokenInfo.Active {
		fmt.Printf("Error during token introspection: %v\n", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Check if the token has the required scope for accessing the resource
	if !hasScope(tokenInfo.Scope, requiredScope) {
		fmt.Println("Insufficient scope")
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient scope"})
		return
	}

	// Your secured resource (replace with the actual logic and data of your resource)
	securedResource := map[string]interface{}{
		"message":   "This is a secured resource",
		"client_id": tokenInfo.ClientID, // Use the client_id attribute for M2M token
	}

	c.JSON(http.StatusOK, securedResource)
}

// / Function to introspect the token using Hydra
func introspectToken(token string) (*model.TokenIntrospect, error) {
	// Create the request to introspect the token
	token = strings.TrimPrefix(token, "Bearer ")
	req, err := http.NewRequest("POST", hydraAdminURL, strings.NewReader("token="+token+"&scope="+requiredScope))
	if err != nil {
		fmt.Printf("Error creating introspection request: %v\n", err)
		return nil, err
	}

	// Set the required headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Perform the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error during HTTP request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Decode the response body into TokenIntrospect struct
	var tokenInfo model.TokenIntrospect
	if err := json.NewDecoder(resp.Body).Decode(&tokenInfo); err != nil {
		fmt.Printf("Error decoding response body: %v\n", err)
		return nil, err
	}

	return &tokenInfo, nil
}

// Function to check if the token has the required scope
func hasScope(tokenScope string, requiredScope string) bool {
	scopes := strings.Fields(tokenScope)
	for _, scope := range scopes {
		if scope == requiredScope {
			return true
		}
	}
	return false
}
