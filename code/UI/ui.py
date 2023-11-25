





def main():
    """
    Main function to show available networks and connect to a user-specified network.
    """
    show_available_networks()

    ssid = input("Enter the SSID that you want to connect to: ")
    password = input("Enter the password to that SSID: ")
    connect_to_wifi(ssid, password)


if __name__ == "__main__":
    main()
