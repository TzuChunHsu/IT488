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

process_question_block() {
    local answer_file="${username}_answers.csv"
    local -a block=("${@:1:$(($#-1))}")

    for question in "${block[@]}"; do
        echo "$question"
        local options=()

        while read -r option; do
            [[ -z "$option" ]] && break
            options+=("$option")  
        done

        while true; do
            echo "Please enter a, b, c, or d: "
            read ans < /dev/tty
            if [[ "$ans" == "a" || "$ans" == "b" || "$ans" == "c" || "$ans" == "d" ]]; then
                echo "$question" >> "$answer_file"

                for ((i=0; i<${#options[@]}; i++)); do
                    if [[ "$ans" == "a" && $i -eq 0 ]]; then
                        echo "${options[$i]} -> YOUR ANSWER" >> "$answer_file"
                    elif [[ "$ans" == "b" && $i -eq 1 ]]; then
                        echo "${options[$i]} -> YOUR ANSWER" >> "$answer_file"
                    elif [[ "$ans" == "c" && $i -eq 2 ]]; then
                        echo "${options[$i]} -> YOUR ANSWER" >> "$answer_file"
                    elif [[ "$ans" == "d" && $i -eq 3 ]]; then
                        echo "${options[$i]} -> YOUR ANSWER" >> "$answer_file"
                    else
                        echo "${options[$i]}" >> "$answer_file"
                    fi
                done

                echo "" >> "$answer_file" 
                break
            else
                echo "Invalid input. Please enter a, b, c, or d."
            fi
        done
    done
}


take_survey() {
  echo "==============================="
  echo "         Take Survey"
  echo "==============================="
  echo "Answer the following questions (type a/b/c/d)."

  local question_block=()
  local IFS='' 

  while read -r line; do
    if [[ -z "$line" ]]; then
      if [ ${#question_block[@]} -gt 0 ]; then
        process_question_block "${question_block[@]}" "$answer_file"
        question_block=()
      fi
    else
      question_block+=("$line")
    fi
  done < "$QUESTION_FILE"

  if [ ${#question_block[@]} -gt 0 ]; then
    process_question_block "${question_block[@]}" "$answer_file"
  fi

  echo "Survey complete! Answers saved to $answer_file"
  echo "Press any key to continue..."
  read -n 1
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


process_question_block() {
    local answer_file="${username}_answers.csv"
    local -a block=("${@:1:$(($#-1))}")

    for ((q=0; q<${#block[@]}; q+=5)); do
        local question="${block[q]}"
        local options=("${block[q+1]}" "${block[q+2]}" "${block[q+3]}" "${block[q+4]}")

        echo "$question" >> "$answer_file"

        while true; do
            echo "$question"
            for opt in "${options[@]}"; do
                echo "$opt"
            done

            echo "Please enter a, b, c, or d: "
            read ans < /dev/tty

            case "$ans" in
                a) selected_index=0 ;;
                b) selected_index=1 ;;
                c) selected_index=2 ;;
                d) selected_index=3 ;;
                *) echo "Invalid input. Please enter a, b, c, or d."; continue ;;
            esac

            for ((i=0; i<4; i++)); do
                if [[ $i -eq $selected_index ]]; then
                    echo "${options[$i]} -> YOUR ANSWER" >> "$answer_file"
                else
                    echo "${options[$i]}" >> "$answer_file"
                fi
            done

            echo "" >> "$answer_file"
            break
        done
    done
}


-------------------------------------------------------------------------------------------------------

function take_survey() {
  clear
  echo "Fruit Survey: ${CURRENT_USER}'s Survey"
  echo

  : > "$CURRENT_USER_ANSWER_FILE"

  local questionCount=0

  while IFS= read -r line
  do
    ((questionCount++))

    local formattedQuestion
    formattedQuestion="$(echo -e "$line")"

    clear
    echo "Fruit Survey: ${CURRENT_USER}'s Survey"
    echo
    echo "$formattedQuestion"
    echo

    local answer=""
    while true; do
      read -p "Please choose your option: " answer
      answer="${answer,,}"
      if [[ "$answer" =~ ^[abcd]$ ]]; then
        break
      else
        echo "Invalid response. Please enter a, b, c, or d."
      fi
    done

    local answeredQuestion=""
    case "$answer" in
      a) answeredQuestion="$(echo "$formattedQuestion" | sed 's/a\. \(.*\)/a. \1 -> YOUR ANSWER/')";;
      b) answeredQuestion="$(echo "$formattedQuestion" | sed 's/b\. \(.*\)/b. \1 -> YOUR ANSWER/')";;
      c) answeredQuestion="$(echo "$formattedQuestion" | sed 's/c\. \(.*\)/c. \1 -> YOUR ANSWER/')";;
      d) answeredQuestion="$(echo "$formattedQuestion" | sed 's/d\. \(.*\)/d. \1 -> YOUR ANSWER/')";;
    esac

    # 把最終(含答案)的題目寫入目前使用者回答檔
    echo "$answeredQuestion" >> "$CURRENT_USER_ANSWER_FILE"
  done < "$QUESTION_FILE"

  echo
  echo "Survey complete."
  echo "Please hit any key to continue."
  read -n 1
}

answeredQuestion="$(echo "$line" | sed ':a;N;$!ba;s/\(a\. [^\n]*\)/\1 -> YOUR ANSWER/')"

