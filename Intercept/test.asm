.CODE  ;�����

DisableWriteProtect PROC            ;ȥ��д����
         push  rax;
         push  rbx;

         mov   rax, cr0;
         mov   rbx, rax;
         and   rax, 0FFFEFFFFh;     ; CR0 16 BIT = 0
         mov   cr0, rax;
     

         mov   rax,rcx              ; rcx = pOldAttr
         mov   [rax],rbx
         
         pop   rbx;
         pop   rax;
         ret
DisableWriteProtect ENDP  






EnableWriteProtect  PROC             ;�ָ�д����

         push  rax;
         mov   rax, rcx; 
         mov   cr0, rax;
         pop   rax;
         ret

EnableWriteProtect  ENDP



END     

