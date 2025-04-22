#!/bin/bash

# ANSI color codes for a cool CLI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Print banner
print_banner() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo -e "╔═══════════════════════════════════════════════════╗"
    echo -e "║                                                   ║"
    echo -e "║             ${PURPLE}OPENFORT 7702 CLI${CYAN}                     ║"
    echo -e "║                                                   ║"
    echo -e "╚═══════════════════════════════════════════════════╝${RESET}"
    echo -e ""
}

# Check if .env file exists and all required variables are present
check_env() {
    echo -e "${BOLD}${BLUE}[*] Checking environment setup...${RESET}"
    
    if [ ! -f .env ]; then
        echo -e "${RED}[✗] .env file not found!${RESET}"
        return 1
    fi
    
    # Required variables list
    required_vars=("HOLESKY_RPC_URL" "PRIVATE_KEY_OPENFORT_USER_7702" "HOLESKY_ENTRYPOINT_ADDRESS" "ADDRESS_OPENFORT_USER_ADDRESS_7702")
    
    # Check for required variables, handling both "VAR=" and "export VAR=" formats
    echo -e "${BLUE}Checking for required variables in .env:${RESET}"
    missing=0
    for var in "${required_vars[@]}"; do
        if grep -q "^$var=" .env || grep -q "^export $var=" .env; then
            echo -e "${GREEN}[✓] Found: $var${RESET}"
        else
            echo -e "${RED}[✗] Missing: $var${RESET}"
            missing=1
        fi
    done
    
    if [ $missing -eq 1 ]; then
        echo -e "${RED}[✗] Some required variables are missing!${RESET}"
        return 1
    fi
    
    # Check if we can source the .env file successfully
    echo -e "${BLUE}Trying to source .env file...${RESET}"
    set -a  # Automatically export all variables
    source .env 2>/dev/null
    set +a
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Successfully sourced .env file${RESET}"
    else
        echo -e "${RED}[✗] Error sourcing .env file${RESET}"
        return 1
    fi
    
    echo -e "${GREEN}[✓] Environment setup looks good!${RESET}"
    return 0
}

# Check private key balance
check_balance() {
    echo -e "${BOLD}${BLUE}[*] Checking wallet balance...${RESET}"
    
    # Source the .env file to get variables
    set -a  # Automatically export all variables
    source .env
    set +a
    
    # Check which key to use - either BURNER_KEY or PRIVATE_KEY_OPENFORT_USER_7702
    if [ -n "$PRIVATE_KEY_OPENFORT_USER_7702" ]; then
        PRIVATE_KEY="$PRIVATE_KEY_OPENFORT_USER_7702"
        echo -e "${CYAN}Using BURNER_KEY from .env${RESET}"
    elif [ -n "$PRIVATE_KEY_OPENFORT_USER_7702" ]; then
        PRIVATE_KEY="$PRIVATE_KEY_OPENFORT_USER_7702"
        echo -e "${CYAN}Using PRIVATE_KEY_OPENFORT_USER_7702 from .env${RESET}"
    else
        echo -e "${RED}[✗] No private key found in .env! Need either BURNER_KEY or PRIVATE_KEY_OPENFORT_USER_7702${RESET}"
        return 1
    fi
    
    # Get the address from the private key
    address=$(cast wallet address --private-key $PRIVATE_KEY 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[✗] Invalid private key format${RESET}"
        return 1
    fi
    
    # Get the balance
    balance=$(cast balance $address --rpc-url $HOLESKY_RPC_URL 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[✗] Failed to get balance. Check your RPC URL${RESET}"
        return 1
    fi
    
    # Convert from wei to ETH for display
    balance_eth=$(cast --to-eth $balance 2>/dev/null)
    
    # Check if balance is sufficient (at least 0.01 ETH)
    balance_check=$(cast --to-wei 0.01 eth 2>/dev/null)
    
    echo -e "${CYAN}Address:${RESET} $address"
    echo -e "${CYAN}Balance:${RESET} $balance_eth ETH"
    
    if (( $(echo "$balance < $balance_check" | bc -l) )); then
        echo -e "${RED}[✗] Balance too low! You need at least 0.01 ETH${RESET}"
        return 1
    fi
    
    echo -e "${GREEN}[✓] Balance is sufficient!${RESET}"
    return 0
}

# Deploy command
run_deploy() {
    echo -e "${BOLD}${BLUE}[*] Deploying OpenfortBaseAccount7702V1_4337 contract...${RESET}"
    make deploy
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Deployment successful!${RESET}"
    else
        echo -e "${RED}[✗] Deployment failed!${RESET}"
    fi
}

# Attach command
run_attach() {
    echo -e "${BOLD}${BLUE}[*] Attaching delegator to deployed account...${RESET}"
    make attach
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Attachment successful!${RESET}"
    else
        echo -e "${RED}[✗] Attachment failed!${RESET}"
    fi
}

# Check code command
run_check_code() {
    echo -e "${BOLD}${BLUE}[*] Checking deployed contract code...${RESET}"
    make check code
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Code check successful!${RESET}"
    else
        echo -e "${RED}[✗] Code check failed!${RESET}"
    fi
}

# Initialize command
run_init() {
    echo -e "${BOLD}${BLUE}[*] Initializing deployed account...${RESET}"
    make init
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Initialization successful!${RESET}"
    else
        echo -e "${RED}[✗] Initialization failed!${RESET}"
    fi
}

# Getters command
run_getters() {
    echo -e "${BOLD}${BLUE}[*] Running getters...${RESET}"
    make getters
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Getters successful!${RESET}"
    else
        echo -e "${RED}[✗] Getters failed!${RESET}"
    fi
}

# Deposit entrypoint command
run_deposit() {
    echo -e "${BOLD}${BLUE}[*] Depositing to entrypoint...${RESET}"
    make deposit entrypoint
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Deposit successful!${RESET}"
    else
        echo -e "${RED}[✗] Deposit failed!${RESET}"
    fi
}

# Execute command
run_execute() {
    echo -e "${BOLD}${BLUE}[*] Executing...${RESET}"
    make execute
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Execution successful!${RESET}"
    else
        echo -e "${RED}[✗] Execution failed!${RESET}"
    fi
}

# Run the full deployment process sequentially
run_all() {
    run_deploy && run_attach && run_check_code && run_init && run_getters && run_deposit && run_execute
}

# Main menu
show_menu() {
    print_banner
    echo -e "${BOLD}${YELLOW}Choose an option:${RESET}"
    echo -e "${CYAN}1)${RESET} Check environment & balance"
    echo -e "${CYAN}2)${RESET} Deploy contract"
    echo -e "${CYAN}3)${RESET} Attach delegator"
    echo -e "${CYAN}4)${RESET} Check contract code"
    echo -e "${CYAN}5)${RESET} Initialize contract"
    echo -e "${CYAN}6)${RESET} Run getters"
    echo -e "${CYAN}7)${RESET} Deposit to entrypoint"
    echo -e "${CYAN}8)${RESET} Execute"
    echo -e "${PURPLE}9)${RESET} ${BOLD}Run full deployment process${RESET}"
    echo -e "${RED}0)${RESET} Exit"
    echo -e ""
    echo -n -e "${YELLOW}Enter your choice: ${RESET}"
    read -r choice
    
    case $choice in
        1) check_env && check_balance ;;
        2) check_env && check_balance && run_deploy ;;
        3) run_attach ;;
        4) run_check_code ;;
        5) run_init ;;
        6) run_getters ;;
        7) run_deposit ;;
        8) run_execute ;;
        9) check_env && check_balance && run_all ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option!${RESET}" ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${RESET}"
    read -r
    show_menu
}

# Start the script
show_menu