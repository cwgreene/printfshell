import inspect
import types
import shlex

import traceback

#import readline
import os

#if os.path.exists("./.shell_history"):
#    print("Found history!")
#    readline.read_history_file("./.shell_history")

class ExitException(Exception):
    pass

def Command(obj):
    if not hasattr(obj, '__metadata__'):
        obj.__metadata__ = {}
    obj.__metadata__[Command] = obj.__name__
    print(obj.__metadata__)
    return obj

class Shell:
    def isCommand(self, member):
        if hasattr(member, '__metadata__'):
            if Command in member.__metadata__:
                return True
        return False

    def __init__(self, prompt="$ ", exit="exit"):
        self.prompt = prompt
        self.exit_command = exit
        self.commands = {
            command[0]:command[1] 
            for command in inspect.getmembers(self, predicate=inspect.ismethod)
            if self.isCommand(command[1])
        }
        print(self.commands)

    def runloop(self):
        while True:
            try:
                userinput = input(f"{self.prompt}")
                result = self.evaluate(userinput)
                #print(readline.get_current_history_length())
            except ExitException as e:
                print(e)
                break
            except Exception as e:
                traceback.print_exc()

    def evaluate(self, command):
        command, *parts = shlex.split(command)
        if command == self.exit_command:
            #readline.write_history_file("./.shell_history")
            raise ExitException()
        elif command in self.commands:
            self.commands[command](*parts)

class EchoShell(Shell):
    @Command
    def echo(self, *args):
        print(args)

def main():
    shell = EchoShell()
    shell.runloop()

if __name__ == "__main__":
    main()
