package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MKSx/tlsd/pcap"
	"github.com/spf13/cobra"
)

type Login struct {
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	ChangePassword bool      `json:"change_password"`
	NewPassword    string    `json:"new_password"`
	ApiLogin       bool      `json:"api_login"`
	GrantType      string    `json:"grant_type"`
	Scope          string    `json:"scope"`
	Authorization  string    `json:"authorization"`
	Time           time.Time `json:"time"`
}

func Start(pcap_file string, key string, port int, output string, ignore_user bool, user_list []string) {
	handler, err := pcap.NewPCAPHandler(pcap_file, key, port)

	if err != nil {
		log.Fatal(err)
	}

	var req *http.Request

	last_req := map[string]string{}

	logins := []Login{}

	var username, password, new_password, grant_type, scope, authorization string

	handler.Proccess(func(connectionID string, data string, fromClient bool, tm time.Time) {

		if fromClient {

			fmt.Println(connectionID)
			_, ok := last_req[connectionID]

			if ok {
				data = last_req[connectionID] + data
				delete(last_req, connectionID)
				fmt.Println("Juntou requisições")
			}

			req, err = http.ReadRequest(bufio.NewReader(strings.NewReader(data)))

			if err != nil {
				fmt.Println("Falha ao tentar fazer o parser")
				//fmt.Println(data)
				return
			}
			if req.ContentLength > 0 {

				if !ok {
					_, err := io.ReadAll(req.Body)
					if err != nil {
						//Requisição incompleta
						//fmt.Println(data)
						last_req[connectionID] = data
						fmt.Println("Inseriou parte no last_req")
						return
					}
				}

				err = req.ParseForm()

				if err != nil {
					fmt.Println("Erro ao parsear o form")
					return
				}

				username = strings.ToUpper(req.FormValue("username"))

				password = req.FormValue("password")

				grant_type = req.FormValue("grant_type")

				scope = req.FormValue("scope")

				new_password = req.FormValue("newpassword")

				authorization = ""

				if new_password != "" {

					username = strings.ToUpper(req.FormValue("login"))
					password = req.FormValue("oldpassword")
				} else if grant_type != "" {
					authorization = req.Header.Get("Authorization")
				}

				if username != "" {

					username = strings.TrimSpace(username)
					if ignore_user {
						for i := range user_list {
							if username == user_list[i] {
								log.Printf("Ignorando usuário %s", username)
								continue
							}
						}
					}

					logins = append(logins, Login{
						Username:       username,
						Password:       password,
						ChangePassword: new_password != "",
						NewPassword:    new_password,
						ApiLogin:       grant_type != "",
						GrantType:      grant_type,
						Scope:          scope,
						Authorization:  authorization,
						Time:           tm,
					})

					fmt.Printf("Username: %s | password: %s | From API: %v | Time: %s\n", username, password, grant_type != "", tm)
				}

			}
		}
	})

	handler.Close()

	jsonBytes, err := json.MarshalIndent(logins, "", "  ")
	if err != nil {
		fmt.Println("Erro ao converter para JSON:", err)
		return
	}

	err = os.WriteFile(output, jsonBytes, 0644)

	if err != nil {
		fmt.Println("Erro ao escrever no arquivo:", err)
		return
	}

	fmt.Printf("Dados escritos em %s\n", output)
}

func ReadUsersFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	users := []string{}

	for scanner.Scan() {
		useraname := strings.TrimSpace(strings.ToUpper(scanner.Text()))

		if len(useraname) < 1 {
			continue
		}

		users = append(users, useraname)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func GetCommand() *cobra.Command {
	var pcap_file string
	var port int
	var private_key string
	var output_file string

	var ignore_users string

	cmd := &cobra.Command{
		Use:   "tlsd",
		Short: "Extrai credenciais de um pcap",
		Long:  `Extrai credenciais de um pcap e armazena em um arquivo json`,
		Run: func(cmd *cobra.Command, args []string) {
			if pcap_file == "" || private_key == "" || output_file == "" {
				return
			}

			var user_list []string
			var err error

			if len(ignore_users) > 0 {
				user_list, err = ReadUsersFromFile(ignore_users)

				if err != nil {
					fmt.Println(err)
					fmt.Printf("Falha ao ler o arquivo %s\n", ignore_users)
					return
				}

			}

			Start(pcap_file, private_key, port, output_file, len(user_list) > 0, user_list)
		},
	}

	cmd.Flags().StringVarP(&pcap_file, "pcap", "", "", "arquivo pcap para leitura")
	cmd.Flags().StringVarP(&private_key, "key", "", "", "chave privada do servidor")
	cmd.Flags().IntVarP(&port, "port", "", 443, "porta HTTPS")
	cmd.Flags().StringVarP(&output_file, "output", "", "", "arquivo json de outpu")
	cmd.Flags().StringVarP(&ignore_users, "ignore", "", "", "arquivo com usuários que não seram extraidos do pcap")

	return cmd
}
