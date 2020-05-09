import json
import random
from abc import ABC, abstractmethod
from pathlib import Path


class General(ABC):
    def __temp(self):
        self._temp_path_aplhabet
        self._temp_path_txt
        self._temp_path_key

    @abstractmethod
    def generate_key(self):
        pass

    @abstractmethod
    def encrypt(self):
        pass

    @abstractmethod
    def decrypt(self):
        pass

    def __path_in(self, extension, rw):
        if rw == 'r':
            info = "read: "
        elif rw == 'w':
            info = "write: "
        path = input("Enter path to '" + extension + "' file for " + info)

        bad_symbols = [':', '*', '?', '<', '>', '|']
        for symbol in bad_symbols:
            if symbol in path:
                print("Error: Incorrect symbols in path")
                return -1
        if '/' in path:
            if '\\' in path:
                print("Error: Incorrect symbols in path")
                return -1
        if '\\' in path:
            if '/' in path:
                print("Error: Incorrect symbols in path")
                return -1

        path = str(Path(path))

        if Path(path).suffix == extension:
            return path
        else:
            print(f"Error: Incorrect extension file '{extension}'")
            return -1

    def _get_text(self):
        checker = self.__path_in(".txt", 'r')
        if checker == -1:
            return -1
        self._temp_path_txt = checker

        try:
            with open(self._temp_path_txt, 'r', encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            print("Error: Incorrect '.txt' file")
            return -1
        except PermissionError:
            print("Error: Incorrect path to '.txt' file")
            return -1

    def _get_alph(self, arg=None):
        if arg == "special":
            checker = self.__path_in(".alph", 'r')
            if checker == -1:
                return -1
            self._temp_path_aplhabet = checker

        try:
            with open(self._temp_path_aplhabet, 'r', encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print("Error: Incorrect '.alph' file")
            return -1
        except PermissionError:
            print("Error: Incorrect path to '.alph' file")
            return -1

    def _get_encrypt_text(self):
        checker = self.__path_in(".encrypt", 'r')
        if checker == -1:
            return -1

        try:
            with open(checker, 'r', encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print("Error: Incorrect '.encrypt' file")
            return -1
        except PermissionError:
            print("Error: Incorrect path to '.alph' file")
            return -1

    def _get_key(self, cipher):
        checker = self.__path_in(".key", 'r')
        if checker == -1:
            return -1
        self._temp_path_key = checker

        try:
            with open(self._temp_path_key, 'r', encoding="utf-8") as f:
                z = json.load(f)
                if cipher in z:
                    return z
        except:
            print("Error: Incorrect '.key' file")
            return -1

    def _set_key(self, key):
        checker = self.__path_in(".key", 'w')
        if checker == -1:
            return -1
        self._temp_path_key = checker

        try:
            with open(self._temp_path_key, 'w', encoding="utf-8") as f:
                json.dump(key, f, indent=4, ensure_ascii=False)
        except FileNotFoundError:
            print("Error: Incorrect path to '.key' file")
            return -1
        except PermissionError:
            print("Error: Incorrect path to '.key' file")
            return -1

    def _set_encrypt_text(self, encrypted_text):
        checker = self.__path_in(".txt", 'w')
        if checker == -1:
            return -1
        self._temp_path_txt = checker

        try:
            with open(self._temp_path_txt + ".encrypt", 'w', encoding="utf-8") as f:
                json.dump(encrypted_text, f, indent=4, ensure_ascii=False)
        except FileNotFoundError:
            print("Error: Incorrect path to '.txt' file")
            return -1
        except PermissionError:
            print("Error: Incorrect path to '.txt' file")
            return -1

    def _set_decrypt_text(self, decrypted_text):
        checker = self.__path_in(".txt", 'w')
        if checker == -1:
            return -1
        self._temp_path_txt = checker

        try:
            with open(self._temp_path_txt, 'w', encoding="utf-8") as f:
                f.writelines(decrypted_text)
        except FileNotFoundError:
            print("Error: Incorrect path to '.txt' file")
            return -1
        except PermissionError:
            print("Error: Incorrect path to '.txt' file")
            return -1

    def _set_alph(self, language):
        alph = []
        if language == "eng":
            for i in range(65, 91):
                alph.append(chr(i))
                alph.append(chr(i+32))
        elif language == "rus":
            for i in range(1040, 1072):
                alph.append(chr(i))
                alph.append(chr(i+32))
            alph.insert(12, chr(1025))
            alph.insert(13, chr(1105))
        else:
            print("Error: Incorrect language")
            return -1
        checker = self.__path_in(".alph", 'w')
        if checker == -1:
            return -1
        self._temp_path_aplhabet = checker

        try:
            with open(self._temp_path_aplhabet, 'w', encoding="utf-8") as f:
                json.dump(alph, f, indent=4, ensure_ascii=False)
        except FileNotFoundError:
            print("Error: Incorrect path to '.alph' file")
            return -1
        except PermissionError:
            print("Error: Incorrect path to '.alph' file")
            return -1


class Cipher_1(General):
    def generate_key(self):
        language = input("Choose alphabet language (eng/rus): ")
        checker = self._set_alph(language)
        if checker == -1:
            return -1
        print("The alphabet was generated")

        key = {}
        key["sub_key"] = {}
        cipher = {"cipher": "cipher_1"}
        checker = self._get_alph()
        if checker == -1:
            return -1
        alph = checker

        mix = alph.copy()
        random.shuffle(mix)
        for i in range(len(mix)):
            key["sub_key"][alph[i]] = mix[i]

        key.update(cipher)
        checker1 = self._set_key(key)
        if checker1 == -1:
            return -1

    def encrypt(self):
        checker = self._get_text()
        if checker == -1:
            return -1
        result = {
            "sub_result": list(checker)
        }
        checker1 = self._get_key("cipher")

        if checker1 == -1:
            return -1
        key = checker1

        try:
            if key.get("cipher") != "cipher_1":
                print("Error: Incorrect '.key' file!")
                return -1
        except:
            print("Error: Incorrect cipher in '.key' file!")
            return -1
        cipher = {
            "cipher": key.pop("cipher")
        }

        key = key["sub_key"]

        for i in range(len(result["sub_result"])):
            if result["sub_result"][i] in key:
                result["sub_result"].insert(i, key[result["sub_result"][i]])
                result["sub_result"].pop(i+1)

        result["sub_result"] = ''.join(result["sub_result"])
        result.update(cipher)

        checker2 = self._set_encrypt_text(result)
        if checker2 == -1:
            return -1

    def decrypt(self):
        checker = self._get_encrypt_text()
        if checker == -1:
            return -1
        result = checker

        result["sub_result"] = list(result["sub_result"])

        if result.get("cipher") != "cipher_1":
            print("Error: Incorrect cipher in '.encrypt' file!")
            return -1

        checker1 = self._get_key("cipher")
        if checker1 == -1:
            return -1
        key = checker1

        try:
            if key.get("cipher") != "cipher_1":
                print("Error: Incorrect '.key' file!")
                return -1
        except:
            print("Error: Incorrect cipher in '.key' file!")
            return -1
        key.pop("cipher")

        key = key["sub_key"]

        for i in range(len(result["sub_result"])):
            for k, v in key.items():
                if v == result["sub_result"][i]:
                    result["sub_result"].insert(i, k)
                    result["sub_result"].pop(i+1)
                    break

        checker2 = self._set_decrypt_text(result["sub_result"])
        if checker2 == -1:
            return -1


class Cipher_2(General):
    def generate_key(self):
        key = {}
        key["sub_key"] = []
        try:
            key_len = int(input("Enter key length: "))
            if key_len < 1:
                print("Error: Incorrect key length")
                return -1
        except ValueError:
            print("Error: Incorrect key length")
            return -1

        cipher = {"cipher": "cipher_2"}

        for num in range(key_len):
            key["sub_key"].append(num)
        random.shuffle(key["sub_key"])

        key.update(cipher)
        checker1 = self._set_key(key)
        if checker1 == -1:
            return -1

    def encrypt(self):
        checker = self._get_text()
        if checker == -1:
            return -1
        text = list(checker)

        result = {
            "sub_result": []
        }

        checker1 = self._get_key("cipher")
        if checker1 == -1:
            return -1
        key = checker1

        try:
            if key.get("cipher") != "cipher_2":
                print("Error: Incorrect '.key' file!")
                return -1
        except:
            print("Error: Incorrect cipher in '.key' file!")
            return -1
        cipher = {
            "cipher": key.pop("cipher")
        }

        block = key["sub_key"]

        format_len = len(text)
        text_symbols = []
        for symbol in text:
            if (symbol in text_symbols) == False:
                text_symbols.append(symbol)
        random.shuffle(text_symbols)

        if len(text) % len(block) != 0:
            format_len = len(block) * ((len(text) // len(block)) + 1)
        while len(text) < format_len:
            text.append(random.choice(text_symbols))

        i = 0
        j = 0
        k = 0
        while i < len(text):
            result["sub_result"].append(text[block.index(j) + k])
            i += 1
            j = i % len(block)
            if j == 0:
                k += len(block)

        result["sub_result"] = ''.join(result["sub_result"])
        result.update(cipher)

        checker2 = self._set_encrypt_text(result)
        if checker2 == -1:
            return -1

    def decrypt(self):
        checker = self._get_encrypt_text()
        if checker == -1:
            return -1
        encr_text = checker

        encr_text["sub_result"] = list(encr_text["sub_result"])

        if encr_text.get("cipher") != "cipher_2":
            print("Error: Incorrect cipher in '.encrypt' file!")
            return -1

        checker1 = self._get_key("cipher")
        if checker1 == -1:
            return -1
        key = checker1

        block = key["sub_key"]
        try:
            if key.get("cipher") != "cipher_2":
                print("Error: Incorrect '.key' file!")
                return -1
        except:
            print("Error: Incorrect cipher in '.key' file!")
            return -1

        i = 0
        j = 0
        k = 0
        result = []
        while i < len(encr_text["sub_result"]):
            result.append(encr_text["sub_result"][block[j] + k])
            i += 1
            j = i % len(block)
            if j == 0:
                k += len(block)

        checker2 = self._set_decrypt_text(result)
        if checker2 == -1:
            return -1


class Cipher_3(General):
    def generate_key(self):
        language = input("Choose alphabet language (eng/rus): ")
        checker = self._set_alph(language)
        if checker == -1:
            return -1
        print("The alphabet was generated")

        checker = self._get_alph()
        if checker == -1:
            return -1
        alph = checker

        key = {}
        key["sub_key"] = []
        try:
            key_len = int(input("Enter key length: "))
            if key_len < 1 or key_len > len(alph):
                print("Error: Incorrect key length")
                return -1
        except ValueError:
            print("Error: Incorrect key length")
            return -1

        cipher = {"cipher": 'cipher_3'}

        for i in range(key_len):
            temp = random.choice(alph)
            key["sub_key"].append(alph.index(temp))

        key.update(cipher)

        checker1 = self._set_key(key)
        if checker1 == -1:
            return -1

    def encrypt(self):
        checker = self._get_alph("special")
        if checker == -1:
            return -1
        alph = checker

        checker1 = self._get_text()
        if checker1 == -1:
            return -1
        text = list(checker1)
        result = {
            "sub_result": []
        }

        checker2 = self._get_key("cipher")
        if checker2 == -1:
            return -1
        key = checker2

        try:
            if key.get("cipher") != "cipher_3":
                print("Error: Incorrect '.key' file!")
                return -1
        except:
            print("Error: Incorrect cipher in '.key' file!")
            return -1
        cipher = {
            "cipher": key.pop("cipher")
        }

        block = key["sub_key"]

        format_len = len(text)
        text_symbols = []
        for symbol in text:
            if (symbol in text_symbols) == False:
                text_symbols.append(symbol)
        random.shuffle(text_symbols)

        if len(text) % len(block) != 0:
            format_len = len(block) * ((len(text) // len(block)) + 1)
        while len(text) < format_len:
            text.append(random.choice(text_symbols))

        i = 0
        j = 0
        while i < len(text):
            if text[i] in alph:
                temp = (alph.index(text[i]) + block[j]) % len(alph)
                result["sub_result"].append(alph[temp])
            elif (text[i] in alph) == False:
                result["sub_result"].append(text[i])

            i += 1
            j = i % len(block)

        result["sub_result"] = ''.join(result["sub_result"])
        result.update(cipher)

        checker2 = self._set_encrypt_text(result)
        if checker2 == -1:
            return -1

    def decrypt(self):
        checker = self._get_alph("special")
        if checker == -1:
            return -1
        alph = checker

        checker1 = self._get_encrypt_text()
        if checker1 == -1:
            return -1
        encr_text = checker1

        encr_text["sub_result"] = list(encr_text["sub_result"])

        if encr_text.get("cipher") != 'cipher_3':
            print("Error: Incorrect cipher in '.encrypt' file!")
            return -1

        checker2 = self._get_key("cipher")
        if checker2 == -1:
            return -1
        key = checker2

        block = key["sub_key"]
        try:
            if key.get("cipher") != 'cipher_3':
                print("Error: Incorrect '.key' file!")
                return -1
        except:
            print("Error: Incorrect cipher in '.key' file!")
            return -1
        key.pop("cipher")

        i = 0
        j = 0
        result = []
        while i < len(encr_text["sub_result"]):
            if encr_text["sub_result"][i] in alph:
                temp = (alph.index(
                    encr_text["sub_result"][i]) - block[j]) % len(alph)
                result.append(alph[temp])
            elif (encr_text["sub_result"][i] in alph) == False:
                result.append(encr_text["sub_result"][i])

            i += 1
            j = i % len(block)

        checker2 = self._set_decrypt_text(result)
        if checker2 == -1:
            return -1


class user_interface(Cipher_1, Cipher_2, Cipher_3):
    def __init__(self):
        # print(user_interface.mro())
        self.__f()

    def __f_encrypt(self, CHOICE=None):
        if CHOICE == 1:
            checker = Cipher_1.encrypt(self)

        elif CHOICE == 2:
            checker = Cipher_2.encrypt(self)

        elif CHOICE == 3:
            checker = Cipher_3.encrypt(self)

        if checker == -1:
            return -1
        print("The text was encrypted")

    def __f_decrypt(self, CHOICE=None):
        if CHOICE == 1:
            checker = Cipher_1.decrypt(self)

        elif CHOICE == 2:
            checker = Cipher_2.decrypt(self)

        elif CHOICE == 3:
            checker = Cipher_3.decrypt(self)

        if checker == -1:
            return -1
        print("The text was decrypted")

    def __f_crypt(self, CHOICE=None):
        while True:
            if CHOICE == 1:
                print("Select encryption method:")
            elif CHOICE == 2:
                print("Select decryption method:")

            print("\t1) Replacement")
            print("\t2) Transposition")
            print("\t3) Gamma")
            print("\n\t9) Back")
            choice = input("Your choice: ")

            if CHOICE == 1:
                try:
                    if int(choice) == 1:
                        if self.__f_encrypt(1) == -1:
                            continue
                    elif int(choice) == 2:
                        if self.__f_encrypt(2) == -1:
                            continue
                    elif int(choice) == 3:
                        if self.__f_encrypt(3) == -1:
                            continue
                    elif int(choice) == 9:
                        return -1
                    else:
                        print("Error: Incorrect input")
                        continue
                except ValueError:
                    print("Error: Incorrect input")
                    continue
                break
            elif CHOICE == 2:
                try:
                    if int(choice) == 1:
                        if self.__f_decrypt(1) == -1:
                            continue
                    elif int(choice) == 2:
                        if self.__f_decrypt(2) == -1:
                            continue
                    elif int(choice) == 3:
                        if self.__f_decrypt(3) == -1:
                            continue
                    elif int(choice) == 9:
                        return -1
                    else:
                        print("Error: Incorrect input")
                        continue
                except ValueError:
                    print("Error: Incorrect input")
                    continue
                break

    def __f_gen_key(self, CHOICE=None):
        if CHOICE == 1:
            checker1 = Cipher_1.generate_key(self)

        elif CHOICE == 2:
            checker1 = Cipher_2.generate_key(self)

        elif CHOICE == 3:
            checker1 = Cipher_3.generate_key(self)

        if checker1 == -1:
            return -1
        print("The key was generated")

    def __f1(self):
        while True:
            print("Encrypt / Decrypt?")
            print("\t1) Encrypt")
            print("\t2) Decrypt")
            print("\n\t9) Back")
            choice = input("Your choice: ")
            try:
                if int(choice) == 1:
                    if self.__f_crypt(1) == -1:
                        continue
                elif int(choice) == 2:
                    if self.__f_crypt(2) == -1:
                        continue
                elif int(choice) == 9:
                    return -1
                else:
                    print("Error: Incorrect input")
                    continue
            except ValueError:
                print("Error: Incorrect input")
                continue
            break

    def __f2(self):
        while True:
            print("Generate a key for the following algorithm:")
            print("\t1) Replacement cipher")
            print("\t2) Transposition cipher")
            print("\t3) Gamma cipher")
            print("\n\t9) Back")
            choice = input("Your choice: ")
            try:
                if int(choice) == 1:
                    if self.__f_gen_key(1) == -1:
                        continue
                elif int(choice) == 2:
                    if self.__f_gen_key(2) == -1:
                        continue
                elif int(choice) == 3:
                    if self.__f_gen_key(3) == -1:
                        continue
                elif int(choice) == 9:
                    return -1
                else:
                    print("Error: Incorrect input")
                    continue
            except ValueError:
                print("Error: Incorrect input")
                continue
            break

    def __f(self):
        while True:
            print("Main menu:")
            print("\t1) Encrypt / Decrypt")
            print("\t2) Generate a key")
            print("\n\t9) Exit")
            choice = input("Your choice: ")
            try:
                if int(choice) == 1:
                    if self.__f1() == -1:
                        continue
                elif int(choice) == 2:
                    if self.__f2() == -1:
                        continue
                elif int(choice) == 9:
                    break
                else:
                    print("Error: Incorrect input")
                    continue
            except ValueError:
                print("Error: Incorrect input")
                continue


user_interface()
