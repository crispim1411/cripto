import re

def invert(text):
    """Função destinada a inverter as letras de um texto de acordo com o condizente
    na posição do alfabeto invertido.

    Parâmetros
    ----------
    text : str
        Texto a ser invertido.

    Retorna
    -------
    newText : str
        Texto invertido.
    """
    try:
        print('Criptografia por inversão')
        pattern = re.compile(r'^[a-z]+$')
        cresc = [chr(c) for c in range(ord('a'), ord('z')+1)]
        decresc = [chr(c) for c in range(ord('z'), ord('a')-1, -1)]
        newText = ''
        for caracter in text.lower():
            if pattern.match(caracter):
                newChar = decresc[cresc.index(caracter)]
                newText = newText + newChar
            else:
                newText = newText + caracter

        return newText

    except Exception as e:
        print(f'Erro: {e}')


def rot(text, rotation):
    """Função destinada a rotacionar um texto de acordo com uma cifra

    Parâmetros
    ----------
    text : str
        Texto a ser rotacionado.
    rotation : int
        Número da cifra, positivo para soma e negativo para subtração dos caracteres.

    Retorna
    -------
    newText : str
        Texto rotacionado.
    """
    try:
        print(f'Criptografia por Rotação de {rotation}')
        pattern = re.compile(r'^[a-z]+$')
        newText = ''
        for caracter in text.lower():
            if pattern.match(caracter):
                newChar = chr(ord(caracter) + rotation)
                if ord(newChar) < 97:
                    newChar = chr(ord(newChar) + 26)
                elif ord(newChar) > 122:
                    newChar = chr(ord(newChar) - 26)
                newText += newChar
            else:
                newText += caracter

        return newText

    except Exception as e:
        print(f'Erro: {e}')


def vig(text, passwd, uncript=False):
    """Função destinada a criptografar um texto de acordo com a cifra de Vigenère.

    Parâmetros
    ----------
    text : str
        Texto a ser rotacionado.
    passwd : str
        Senha da cifra.
    uncript : bool
        Caso deseje-se realizar descriptografia, set como True.

    Retorna
    -------
    newText : str
        Texto criptografado pela senha.
    """
    try:
        print('Criptografia por Vigenère')
        pattern = re.compile(r'^[a-z]+$')
        if not pattern.match(passwd):
            raise Exception('Entre com uma senha válida, sem acento ou caracteres especiais.')

        newText = ''
        i = 0
        for caracter in text.lower():
            if i >= len(passwd):
                i = 0
            p = passwd[i]
            if pattern.match(caracter):
                if uncript==True:
                    newChar = chr(ord(caracter)-ord(p)+ord('a'))
                else:
                    newChar = chr(ord(caracter)+ord(p)-ord('a'))
                if ord(newChar) < 97:
                    newChar = chr(ord(newChar) + 26)
                elif ord(newChar) > 122:
                    newChar = chr(ord(newChar) - 26)
                newText += newChar
                i+=1
            else:
                newText += caracter

        return newText

    except Exception as e:
        print(f'Erro: {e}')
