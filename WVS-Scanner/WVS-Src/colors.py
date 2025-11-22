from termcolor import colored

def severity_color(level):
    if level == "HIGH":
        return colored(level, "red")
    elif level == "MEDIUM":
        return colored(level, "yellow")
    elif level == "LOW":
        return colored(level, "green")
    else:
        return colored(level, "cyan")
