import subprocess

NOTIFY_SCRIPT = "./notify.sh"

def notify_computer(message):
    """
    Notifies the computer
    :param message: the message to display on the notification
    :return: None
    """
    subprocess.run(['notify-send', message])


def main():
    notify_computer("s")


if __name__ == "__main__":
    main()