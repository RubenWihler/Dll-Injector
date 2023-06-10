/*
* RUBEN WIHLER
* 03.06.2023
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#define COLOR_CYAN    "\x1b[36m"
#define COLOR_ORANGE  "\x1b[33m"
#define COLOR_DARKORANGE "\x1b[38;5;208m"
#define COLOR_RESET   "\x1b[0m"

const char* e = "\x1b[31m[-]";
const char* s = "\x1b[32m[+]";
const char* i = "\x1b[36m[*]";
const char* w = "\x1b[33m[!]";

const char* title = 
"\n\n\x1b[38;5;208m ___   _     _\x1b[36m       ___  _  _     _  ___  ___  _____   ___   ___ \n"
"\x1b[38;5;208m|   \\ | |   | |\x1b[36m     |_ _|| \\| | _ | || __|/ __||_   _| / _ \\ | _ \\\n"
"\x1b[38;5;208m| |) || |__ | |__ \x1b[36m   | | | .` || || || _|| (__   | |  | (_) ||   /\n"
"\x1b[38;5;208m|___/ |____||____|\x1b[36m  |___||_|\\_| \\__/ |___|\\___|  |_|   \\___/ |_|_\\\n"
"------------------------------------------------------------------\n"
"RUBEN WIHLER                                                 V.0.1\n";
                                                                                                                                                

size_t getFileSize(char* path);
bool FileExists(const std::string& filename);
bool loadDll(char* path);
bool loadDllInProcess(DWORD PID, char* path);

int main(int argc, char* argv[]) 
{
	if (argc < 2 || argc > 3) {
		printf("%s format : %s <DLL_PATH> [PID] %s", e, argv[0], COLOR_RESET);
		return EXIT_FAILURE;
	}

	if (!FileExists(argv[1])) {
		printf("%s le chemin vers la dll est invalide ! %s", e, COLOR_RESET);
		return EXIT_FAILURE;
	}

	printf("%s %s %s\n\n\n", COLOR_CYAN, title, COLOR_RESET);

	char* path = (char*)malloc(MAX_PATH);
	GetFullPathNameA(argv[1], MAX_PATH, path, NULL);

	if (argc == 3) 
	{
		DWORD PID;
		PID = atoi(argv[2]);

		if (PID == 0) 
		{
			printf("%s le PID est invalide ! %s", e, COLOR_RESET);
			return EXIT_FAILURE;
		}

		return loadDllInProcess(PID, path) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	return loadDll(path) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/// @brief Retourne la taille d'un fichier
/// @param path chemin du fichier
/// @return taille du fichier en bits
size_t getFileSize(char* path)
{
	FILE* file = NULL;
	size_t size = 0;

	file = fopen(path, "rb");

	if (file == NULL)
	{
		printf("%s impossible d'ouvrir le fichier, erreur: %ld %s", e, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fseek(file, 0, SEEK_SET);

	fclose(file);

	return size;
}

/// @brief Verifie si un fichier existe
/// @param filename chemin du fichier
/// @return le fichier existe ou non
bool FileExists(const std::string& filename)
{
	WIN32_FIND_DATAA fd = { 0 };
	HANDLE hFound = FindFirstFileA(filename.c_str(), &fd);
	bool retval = hFound != INVALID_HANDLE_VALUE;
	FindClose(hFound);

	return retval;
}

/// @brief Charge une DLL dans le processus
/// @param dllPath chemin de la DLL
/// @return reussite ou echec
bool loadDll(char* path)
{
	HINSTANCE hDll;
	size_t dll_size = getFileSize(path);

	printf(
		"%s Informations :\n"
		"  --> DLL : \x1b[38;5;208m%s\n\x1b[36m"
		"  --> Taille de la DLL : \x1b[33m%zu-octets\n\n%s"
		, i, path, dll_size, COLOR_RESET
	);

	hDll = LoadLibrary(path);

	if (hDll == NULL)
	{
		printf("%s impossible de charger la dll, erreur: %ld %s", e, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	printf("%s la dll a ete chargee avec succes !\n%s", s, COLOR_RESET);
	return TRUE;
}

/// @brief Charge une DLL dans un processus existant
/// @param dllPath chemin de la DLL
/// @param PID PID du processus
/// @return reussite ou echec
bool loadDllInProcess(DWORD PID, char* path)
{
	DWORD TID = NULL;
	LPVOID buffer = NULL;
	HMODULE hKernel32 = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	wchar_t dllPath[MAX_PATH] = L"";
	mbstowcs(dllPath, path, MAX_PATH);

	size_t dll_size = getFileSize(path);
	size_t dllPathSize = sizeof(dllPath);

	printf("%s tentative d'ouverture d'un handle sur le processus (%ld)\n", i, PID);
	
	//ouvre un handle sur le processus
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (hProcess == NULL)
	{
		printf("%s impossible d'ouvrir un handle sur le processus (%ld), erreur: %ld %s", e, PID, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	printf("%s a obtenu un acces au processus !\n\--> 0x%p\n%s", s, hProcess, COLOR_RESET);


	printf("%s allocation de %zu-octets avec les permissions PAGE_READWRITE dans le processus (%ld)\n", i, dllPathSize, PID);
	//alloue de la memoire dans le processus distant
	buffer = VirtualAllocEx(hProcess, NULL, dllPathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

	if (buffer == NULL)
	{
		printf("%s impossible de creer le buffer, erreur: %ld %s", e, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	printf("%s ecriture de [\x1b[33m%S\x1b[36m] dans la memoire du processus (%ld)\n", i, dllPath, PID);
	//ecrit le chemin de la dll dans le processus distant
	WriteProcessMemory(hProcess, buffer, dllPath, dllPathSize, NULL);


	printf("%s recuperation du module Kernel32.dll dans le processus (%ld)\n", i, PID);
	//recupere l'adresse du module kernel32.dll dans le processus distant
	hKernel32 = GetModuleHandleW(L"Kernel32");

	if (hKernel32 == NULL)
	{
		printf("%s impossible de recuperer le module kernel32.dll dans le processus (%ld), erreur: %ld %s", e, PID, GetLastError(), COLOR_RESET);
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("%s recuperation du module Kernel32.dll dans le processus (%ld) reussie !\n\\---> 0x%p\n%s", s, PID, hKernel32, COLOR_RESET);


	printf("%s recuperation de l'adresse de la fonction LoadLibraryW dans le processus (%ld)\n", i, PID);
	//recupere l'adresse de la fonction LoadLibraryW dans le processus distant
	LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	printf("%s recuperation de l'adresse de la fonction LoadLibraryW dans le processus (%ld) reussie !\n\\---> 0x%p\n%s", s, PID, lpStartAddress, COLOR_RESET);


	printf("%s creation d'un thread dans le processus (%ld)\n", i, PID);
	//cree un thread dans le processus distant
	hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, buffer, 0, &TID);

	if (hThread == NULL)
	{
		printf("%s impossible de creer un thread dans le processus (%ld), erreur: %ld %s", e, PID, GetLastError(), COLOR_RESET);
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("%s creation d'un thread dans le processus (%ld) reussie !\n\\---> 0x%p\n%s", s, PID, hThread, COLOR_RESET);

	printf(
		"%s Informations :\n"
		"  --> Processus : \x1b[38;5;208m%ld\x1b[36m\n"
		"  --> DLL : \x1b[38;5;208m%S\x1b[36m\n"
		"  --> Taille de la DLL : \x1b[33m%zu-octets\x1b[36m\n"
		"  --> Adresse de la DLL : \x1b[33m0x%p\x1b[36m\n"
		"  --> Adresse du module Kernel32.dll : \x1b[33m0x%p\x1b[36m\n"
		"  --> Adresse de la fonction LoadLibraryW : \x1b[33m0x%p\x1b[36m\n"
		"  --> Handle du processus : \x1b[33m0x%p\x1b[36m\n"
		"  --> Handle du thread : \x1b[33m0x%p\x1b[36m\n"
		"  --> Thread ID : \x1b[33m%ld\n%s"
		, i, PID, dllPath, dll_size, buffer, hKernel32, lpStartAddress, hProcess, hThread, TID, COLOR_RESET
	);


	printf("%s attente de la fin du thread dans le processus \x1b[33m(%ld)\n", i, PID);
	//attend la fin du thread
	WaitForSingleObject(hThread, INFINITE);
	printf("%s le thread a ete execute avec succes dans le processus (%ld)\n%s", s, PID, COLOR_RESET);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	printf("%s l'injection a ete effectuee avec succes !\n%s", s, COLOR_RESET);
	return TRUE;
}
