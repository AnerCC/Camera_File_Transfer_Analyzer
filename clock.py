import datetime
import time
import os

# Original ASCII art for digits (single size)
# Each digit is 5 lines high and about 5 chars wide
ORIGINAL_DIGITS = {
    '0': [" AAA ", "A   A", "A   A", "A   A", " AAA "],
    '1': ["  A  ", " AA  ", "  A  ", "  A  ", " AAA "],
    '2': [" AAA ", "    A", " AAA ", "A    ", " AAA "],
    '3': [" AAA ", "    A", "  AA ", "    A", " AAA "],
    '4': ["A   A", "A   A", " AAA ", "    A", "    A"],
    '5': [" AAA ", "A    ", " AAA ", "    A", " AAA "],
    '6': [" AAA ", "A    ", " AAA ", "A   A", " AAA "],
    '7': ["AAAAA", "    A", "   A ", "  A  ", " A   "],
    '8': [" AAA ", "A   A", " AAA ", "A   A", " AAA "],
    '9': [" AAA ", "A   A", " AAA ", "    A", " AAA "]
}

# Original ASCII art for separators (single size)
ORIGINAL_SEPARATOR_DOT = ["     ", "  .  ", "     ", "  .  ", "     "]
ORIGINAL_SEPARATOR_DASH = ["     ", " --- ", "     ", " --- ", "     "]

def scale_char_art(original_art):
    """
    Scales a single ASCII art character by duplicating lines and characters.
    Each line is duplicated, and each character within a line is duplicated.
    """
    scaled_art = []
    for line in original_art:
        scaled_line = ""
        for char_in_line in line:
            scaled_line += char_in_line * 2 # Duplicate each character horizontally
        scaled_art.append(scaled_line) # Add the scaled line
        scaled_art.append(scaled_line) # Duplicate the line vertically

    return scaled_art

# Generate the scaled (double-sized) ASCII art
SCALED_DIGITS = {digit: scale_char_art(ORIGINAL_DIGITS[digit]) for digit in ORIGINAL_DIGITS}
SCALED_SEPARATOR_DOT = scale_char_art(ORIGINAL_SEPARATOR_DOT)
SCALED_SEPARATOR_DASH = scale_char_art(ORIGINAL_SEPARATOR_DASH)

# Each scaled char now has 10 lines (5 original * 2 scaling factor)
SCALED_CHAR_HEIGHT = len(SCALED_DIGITS['0']) # Should be 10

def get_large_char(char):
    if char.isdigit():
        return SCALED_DIGITS[char]
    elif char == '.':
        return SCALED_SEPARATOR_DOT
    elif char == '-':
        return SCALED_SEPARATOR_DASH
    else:
        # Fallback for unexpected chars, also scaled
        return scale_char_art(["     "] * 5)

def display_large_time(time_string):
    chars = list(time_string)

    # Initialize display lines based on the scaled character height
    display_lines = [""] * SCALED_CHAR_HEIGHT

    for char in chars:
        large_char_art = get_large_char(char)
        for i in range(SCALED_CHAR_HEIGHT):
            # Add a bit more space between scaled characters for clarity
            display_lines[i] += large_char_art[i] + "  "

    for line in display_lines:
        print(line)

while True:
    now = datetime.datetime.now()
    # Ensure milliseconds are always 3 digits
    time_str = now.strftime("%H-%M-%S") + f".{now.microsecond // 1000:03d}"

    os.system('cls' if os.name == 'nt' else 'clear') # Clears the screen

    display_large_time(time_str)

    # Wait for a short period. You might want to increase this slightly
    # as larger text can make fast updates look jumpy.
    time.sleep(0.01) # Update every 50 milliseconds