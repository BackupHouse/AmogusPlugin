#include  "AADebugBad.h"

int main()
{
	SetConsoleTextAttribute((GetStdHandle)(STD_OUTPUT_HANDLE), FOREGROUND_GREEN); // for fun

	SetConsoleTitleW(L"[SecureEngine] advanced anti-anti-anti-debug tool");//themida mem 
	
	std::cout << "Is bad hook NtSystemDebugControl ->\t " << BadCode::IsSystemDebugHook() << '\n';
	std::cout << "Debug flag is hooked ->\t " << BadCode::IsDebugFlagHooked() << '\n';
	std::cout << "Breakpoint bad ->\t" << BadCode::IsBadHideContext() << '\n'; 
	std::cout << "Thread hide bad ->\t" << BadCode::IsBadThreadHide() << '\n';
	std::cout << "Number object bad  hook->\t" << BadCode::IsBadHookNumberObject() << '\n';
	
	std::cin.get(); 

}