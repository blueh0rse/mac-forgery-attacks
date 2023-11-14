import subprocess
from Crypto.Random import get_random_bytes


# custom function to open a file
def open_file(dat_file, mode, data="No data!"):
    # open_file("dat_file", 'r')
    with open(dat_file, mode) as file:
        if mode == "rb" or mode == "r":
            content = file.read()
            return content
        elif mode == "w":
            file.write(data)


# custom function to execute bash commands
def exec_bash(cmd, tag="PRINT", output=False):
    result = subprocess.check_output(cmd, shell=True, text=True)
    if output:
        print(f"[{tag}]: {result}")


# custom function to detect padding
def check_padding(dat_file):
    print(f"Checking padding for: {dat_file}")
    content = open_file(dat_file, "rb")
    content = content[::-1]
    count = 0
    for char in content:
        if char == ".":
            count += 1
        elif char == "\n":
            continue
        else:
            break
    print(f"padding = {count} zero-bytes")
    return count


def main():
    # data initialization
    header = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    key = get_random_bytes(16)
    message1 = "What about joining me tomorrow for dinner?"
    message2 = (
        "Oops, Sorry, I just remember that I have a meeting very soon in the morning."
    )

    print(f"Message 1: {message1}")
    print(f"Message 2: {message2}")

    # add header to messages
    h_msg1 = header + message1
    h_msg2 = header + message2

    # write data in files
    open_file("key.dat", "w", key.hex())  # key
    open_file("head.dat", "w", header)  # header
    open_file("mess1.dat", "w", message1)  # message1
    open_file("mess2.dat", "w", message2)  # message2
    open_file("h_msg1.dat", "w", h_msg1)  # header + message1
    open_file("h_msg2.dat", "w", h_msg2)  # header + message2

    # Generate the corresponding AES-128-CBC-MACs for the 2 messages with headers
    # and store them into tag1.dat and tag2.dat.

    # compute AES-128-CBC-MACs for (header + message1)
    exec_bash(
        "openssl enc -aes-128-cbc -K $(cat key.dat) -iv 0 -in h_msg1.dat | tail -c 16 > tag1.dat"
    )
    exec_bash("xxd tag1.dat > xtag1.dat")

    # compute AES-128-CBC-MACs for (header + message2)
    exec_bash(
        "openssl enc -aes-128-cbc -K $(cat key.dat) -iv 0 -in h_msg2.dat | tail -c 16 > tag2.dat"
    )
    exec_bash("xxd tag2.dat > xtag2.dat")

    # investigate message1 padding
    exec_bash(
        "openssl enc -aes-128-cbc -K $(cat key.dat) -iv 0 -in h_msg1.dat -out cipher1.dat"
    )
    exec_bash(
        "openssl enc -d -aes-128-cbc -K $(cat key.dat) -iv 0 -nopad -in cipher1.dat -out padded1.dat"
    )
    exec_bash("xxd padded1.dat > xpadded1.dat")

    padding = "\x06\x06\x06\x06\x06\x06"
    open_file("padding.dat", "w", padding)  # padding

    # Create the forgery by appending the files:
    # head.dat, mess1.dat, the necessary padding for the first message, the tag tag1.dat and the second message mess2.dat
    # Store it into forgery.dat.
    # Compute the CBC-MAC of the resulting file
    # and check whether it is exactly the same as tag2.dat.

    exec_bash("cat head.dat mess1.dat padding.dat tag1.dat mess2.dat > forgery.dat")
    exec_bash(
        "openssl enc -aes-128-cbc -K $(cat key.dat) -iv 0 -in forgery.dat | tail -c 16 > forged.dat"
    )
    exec_bash("xxd forged.dat > xforged.dat")

    exec_bash("echo Tag2: && cat xtag2.dat", "PRINT", True)
    exec_bash("echo Forged: && cat xforged.dat", "PRINT", True)


if __name__ == "__main__":
    main()
