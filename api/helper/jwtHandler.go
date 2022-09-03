package helper

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"vuln-info-backend/service/auth"
)

func AuthorizeJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := GetToken(c)
		if err == nil {
			if token.Valid {
				claims := token.Claims.(jwt.MapClaims)
				usr := claims["name"].(string)
				log.Println(usr)
			} else {
				fmt.Println(err)
				c.AbortWithStatus(http.StatusUnauthorized)

			}
		} else {
			fmt.Println(err)
			c.AbortWithStatus(http.StatusUnauthorized)

		}
	}

}

func GetToken(c *gin.Context) (*jwt.Token, error) {
	const BEARER_SCHEMA = "Bearer"
	authHeader := c.GetHeader("Authorization")
	if len(authHeader) < 7 {
		c.AbortWithStatus(http.StatusUnauthorized)
		return nil, errors.New("invalid header")

	}
	tokenString := authHeader[len(BEARER_SCHEMA)+1:]
	token, err := auth.ValidateToken(tokenString)

	return token, err
}

func GetUserStringFromToken(c *gin.Context) string {
	token, _ := GetToken(c)
	claims := token.Claims.(jwt.MapClaims)
	usr := claims["name"].(string)

	return usr
}
