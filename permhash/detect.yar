rule M_Hunting_IPA_1
{	
        meta:		
            author = "jaredswilson"        
            description = "Help identify IPA files."        
            md5 = "ddbac462c5a5c21c0c4811597d292679"        
            date_created = "2024-03-04"	
        strings:		
            $header = { 50 4B 03 04 }		
            $app = ".app/"		
            $pl = "Payload/"		
            $plist = "Info.plist"		
            $re = /Payload\/[^\/]+\.app/	
        condition:		
            $header at 0 and all of them
}

rule M_Hunting_MachO_Entitlements_1
{    
        meta:    	
            author = "jaredswilson"        
            description = "Help identify Mach-O files with entitlements."        
            md5 = "4ef9738b7c319c9b65f245cbbf340627"        
            date_created = "2024-03-04"    
        strings:        
            $entitlement_magic = {fa de 71 71}        
            $plist = "<plist"        
            $dict = "<dict"    
        condition:        
            ((uint32(0) == 0xcafebabe) or (uint32(0) == 0xfeedface) or (uint32(0) == 0xfeedfacf) or 
            (uint32(0) == 0xbebafeca) or (uint32(0) == 0xcefaedfe) or (uint32(0) == 0xcffaedfe)) and 
            (all of them) and         
            for any i in (1..#plist) : ((@plist[i] > @entitlement_magic) and (@plist[i] < @entitlement_magic + 300))
}