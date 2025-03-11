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
    local answer_file="${username}_answers.csv"
    echo "Fruit Survey: Taking Survey"
    rm -f "$answer_file"
    
    while IFS= read -r line; do
        echo "$line"
        read -p "Your answer: " answer
        echo "$line -> YOUR ANSWER: $answer" >> "$answer_file"
    done < "$QUESTION_FILE"
    
    echo "Survey completed!"
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




