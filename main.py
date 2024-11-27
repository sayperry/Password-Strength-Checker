import tkinter as tk
from tkinter import messagebox
import re

# Common passwords to disallow
import tkinter as tk
from tkinter import messagebox
import re

# Initialize common passwords to disallow
COMMON_PASSWORDS = {
    "password", "123456", "1234567", "12345678", "12345", "1234", "123", "1q2w3e4r", "qwertyuiop", 
    "iloveyou", "111111", "123321", "abc123456", "password123", "qwerty123", "letmein1", "welcome1", 
    "admin123", "monkey", "sunshine", "123123", "qwerty1", "football", "princess", "qazwsx", "123qwe", 
    "1qaz2wsx", "password!", "trustno1", "1234567890", "123qweasd", "1q2w3e", "qwertyui", 
    "1qazxsw2", "qwert", "abc12345", "1qaz2wsx3edc", "1qazxsw2cde", "qwerty12345", "password1", 
    "qwerty123456", "qazwsxdcrv", "123456789qwerty", "1234567890qwerty", "qwertyuiop123", 
    "1234567890qwert", "1234567890asdf", "password2", "qwe123", "qwertyuiop1", "asdfgh", 
    "asdf123", "1qaz2wsx3edc4rfv", "zxcvbnm", "zxcvbn", "zxcvbn123", "zxcvbnm123", "abc1234", 
    "abc12345", "abc123456", "abc123456789", "abc1234567890", "password3", "letmein123", 
    "qwerty1234", "qwerty12345", "qwerty123456", "qwerty123456789", "qwerty1234567890", 
    "12345abcde", "123456abc", "123456abcdef", "1qazxswedc", "1qazxsw", "1qazxsw2", 
    "1qazxsw3", "1qazxsw4", "1qazxsw5", "1qazxsw6", "1qazxsw7", "1qazxsw8", "1qazxsw9", 
    "1qazxsw0", "1qazxswq", "1qazxswq1", "1qazxswq2", "1qazxswq3", "1qazxswq4", "1qazxswq5", 
    "1qazxswq6", "1qazxswq7", "1qazxswq8", "1qazxswq9", "1qazxswq0", "1qazxswq1q", 
    "1qazxswq2q", "1qazxswq3q", "1qazxswq4q", "1qazxswq5q", "1qazxswq6q", "1qazxswq7q", 
    "1qazxswq8q", "1qazxswq9q", "1qazxswq0q", "1qazxswq1q2", "1qazxswq2q3", "1qazxswq3q4", 
    "1qazxswq4q5", "1qazxswq5q6", "1qazxswq6q7", "1qazx"}

def check_password_strength(password):
    """Check the strength of the provided password and return feedback."""
    feedback = []
    if len(password) < 8:
        feedback.append("Weak: Password must be at least 8 characters long.")
    if not re.search(r"[A-Za-z]", password):
        feedback.append("Weak: Password must contain letters.")
    if not re.search(r"[0-9]", password):
        feedback.append("Weak: Password must contain numbers.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        feedback.append("Weak: Password must contain special characters.")
    if password in COMMON_PASSWORDS:
        feedback.append("Weak: Password is too common. Choose a more unique password.")
    
    if not feedback:
        return "Strong: Your password is strong!"
    return "\n".join(feedback)

def check_password():
    """Check the password and display its strength."""
    password = entry.get()
    strength = check_password_strength(password)
    
    # Show detailed feedback
    messagebox.showinfo("Password Strength", strength)
    
    # Update strength meter
    update_strength_meter(password)

def update_strength_meter(password):
    """Update the visual strength meter based on password strength."""
    strength_score = 0
    if len(password) >= 8:
        strength_score += 1
    if re.search(r"[A-Za-z]", password):
        strength_score += 1
    if re.search(r"[0-9]", password):
        strength_score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength_score += 1
    if password not in COMMON_PASSWORDS:
        strength_score += 1

    # Update the strength meter
    meter_label.config(text=f"Strength: {strength_score}/5", bg=get_meter_color(strength_score))

def get_meter_color(score):
    """Return color based on strength score."""
    if score == 5:
        return "green"
    elif score >= 3:
        return "yellow"
    else:
        return "red"

# Create the main window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x400")
root.configure(bg="#e0f7fa")


# Add a title label
title_label = tk.Label(root, text="Password Strength Checker", font=("Helvetica", 18, "bold"), bg="#e0f7fa", fg="#00796b")
title_label.pack(pady=20)



# Add a label for password entry
label = tk.Label(root, text="Enter your password:", font=("Arial", 12), bg="#e0f7fa", fg="#004d40")
label.pack(pady=5)

# Add an entry field for the password
entry = tk.Entry(root, show='*', font=("Arial", 12), width=30, bd=2, relief="groove")
entry.pack(pady=5)

# Add a button to check password strength
button = tk.Button(root, text="Check Strength", command=check_password, font=("Arial", 12), bg="#4CAF50", fg="white")
button.pack(pady=20)

# Add a label to display password strength meter
meter_label = tk.Label(root, text="Strength: 0/5", font=("Arial", 12), bg="#e0f7fa", fg="#004d40")
meter_label.pack(pady=10)

# Add a footer label with password guidelines
guidelines_label = tk.Label(root, text="Guidelines for a strong password:\n- At least 8 characters\n- Mix of letters, numbers, and symbols\n- Avoid common passwords", font=("Arial", 10), bg="#e0f7fa", fg="#004d40")
guidelines_label.pack(pady=10)

# Run the application
root.mainloop()
