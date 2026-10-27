.code 

__lgdt proc
	lgdt fword ptr [rcx]
	ret
__lgdt endp

__lldt proc
	lldt cx
	ret
__lldt endp

__ltr proc
	ltr cx
	ret
__ltr endp

__sgdt proc
	sgdt fword ptr [rcx]
	ret
__sgdt endp

__sldt proc
	sldt word ptr [rcx]
	ret
__sldt endp

__str proc
	str word ptr [rcx]
	ret
__str endp

end