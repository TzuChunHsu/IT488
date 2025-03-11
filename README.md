#!/bin/bash

CREDENTIALS_FILE="user_credentials.csv"
QUESTION_FILE="question_bank.csv"

function register() {
    echo "Fruit Survey: Registration"
    read -p "Enter your username: " username
    
    if grep -q "^$username," "$CREDENTIALS_FILE"; then
        echo "Username '$username' already exists. Try another."
        return
    fi
    
    while true; do
        read -s -p "Enter your password (8+ chars, 1 number, 1 symbol): " password
        echo
        read -s -p "Re-enter your password: " password2
        echo

        if [[ "$password" != "$password2" ]]; then
            echo "Passwords do not match!"
        elif [[ ${#password} -lt 8 || ! "$password" =~ [0-9] || ! "$password" =~ [^a-zA-Z0-9] ]]; then
            echo "Password must be at least 8 characters long, contain a number and a symbol."
        else
            echo "$username,$password" >> "$CREDENTIALS_FILE"
            echo "Registration successful!"
            break
        fi
    done
}

function login() {
    echo "Fruit Survey: Login"
    read -p "Username: " username
    read -s -p "Password: " password
    echo
    
    if grep -q "^$username,$password" "$CREDENTIALS_FILE"; then
        echo "Login successful!"
        survey_menu "$username"
    else
        echo "Invalid username or password."
    fi
}

function take_survey() {
  local username="$1"
  local answer_file="${username}_answers_file.csv"

  > "$answer_file"

  echo "============================="
  echo "         Take Survey"
  echo "============================="
  echo "Answer the following questions (type a/b/c/d)."

  local question_block=()
  local IFS=''  
  while read -r line || [[ -n "$line" ]]; do
 
    if [[ -z "$line" ]]; then
      process_question_block question_block[@] "$answer_file"
      question_block=()
    else
      question_block+=("$line")
    fi
  done < "$QUESTION_FILE"

  if [ ${#question_block[@]} -gt 0 ]; then
    process_question_block question_block[@] "$answer_file"
  fi

  echo "Survey complete! Answers saved to $answer_file"
  echo "Press any key to continue..."
  read -n 1
}

function process_question_block() {
 
  local -n block="$1"   
  local answer_file="$2"


  for line in "${block[@]}"; do
    echo "$line"
  done


  local ans
  while true; do
    read -p "Please choose (a/b/c/d): " ans
    ans=$(echo "$ans" | tr '[:upper:]' '[:lower:]')  
    if [[ "$ans" =~ ^[abcd]$ ]]; then
      break
    else
      echo "Invalid input. Please enter a, b, c, or d."
    fi
  done


  for line in "${block[@]}"; do
    local first_char="${line%%.*}"  
    local trimmed="${first_char//[[:space:]]/}" #

    if [ "$trimmed" == "$ans" ]; then
      echo "${line} -> YOUR ANSWER" >> "$answer_file"
    else
      echo "$line" >> "$answer_file"
    fi
  done

  echo "" >> "$answer_file"  
  echo
}

function view_survey() {
    local username="$1"
    local answer_file="${username}_answers.csv"
    
    if [[ ! -f "$answer_file" ]]; then
        echo "No survey answers found. Please take the survey first."
    else
        echo "Fruit Survey: Viewing Your Answers"
        cat "$answer_file"
    fi
}

function survey_menu() {
    local username="$1"
    while true; do
        echo -e "\nFruit Survey: $username's Menu"
        echo "1. Take Survey"
        echo "2. View Survey"
        echo "3. Logout"
        read -p "Choose an option: " choice
        
        case "$choice" in
            1) take_survey "$username" ;;
            2) view_survey "$username" ;;
            3) break ;;
            *) echo "Invalid option." ;;
        esac
    done
}

function main_menu() {
    while true; do
        echo -e "\nFruit Survey: Main Menu"
        echo "1. Register"
        echo "2. Login"
        echo "3. Exit"
        read -p "Choose an option: " choice
        
        case "$choice" in
            1) register ;;
            2) login ;;
            3) exit 0 ;;
            *) echo "Invalid option." ;;
        esac
    done
}

main_menu

1. Which one of these is a fruit?\na. Apple\nb. Onion\nc. Tomato\nd. Cabbage

2. Which one of these is red?\na. Apple\nb. Onion\nc. Orange\nd. Cabbage

3. Which one of these is not a fruit?\na. Garlic\nb. Grape\nc. Cranberry\nd. Kiwi

4. Which one of these is yellow?\na. Orange\nb. Banana\n\nc. Mango\nd. Cabbage

5. Which one of these is a vegetable?\na. Carrot\nb. Banana\nc. Potato\n\nd. Onion




