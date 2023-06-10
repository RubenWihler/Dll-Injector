# Dll-Injector

## Description

Un simple injecteur de DLL en C++.
Il est possible de choisir le processus cible, la DLL à injecter et la fonction à appeler.

## Utilisation
Arguments:
    1: Chemin de la DLL à injecter
    2: Nom du processus cible [Optionnel]

Le premier argument est le chemin de la DLL à injecter.

Le second argument est le PID du processus cible. Si aucun PID n'est spécifié le program chargera la DLL dans le processus courant.

### Exemple
`.\dllInjector.exe .\myDll.dll`
charge la DLL `myDll.dll` dans le processus courant.


`.\dllInjector.exe .\myDll.dll 1234`
charge la DLL `myDll.dll` dans le processus avec le PID `1234`.