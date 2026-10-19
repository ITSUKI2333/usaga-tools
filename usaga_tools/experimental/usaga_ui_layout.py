"""Layout analysis on reachable Japanese bytecode, never on arbitrary byte matches.







All coordinates are native game pixels. A plan is independent of translated text



storage and fonts; apply() works on disposable build resources only.



"""



import collections, re, struct







def returned_length(words):



    """Prove a return copied from an unmodified callee-saved constant.







    0E/0F subhandlers return their byte count rather than advancing the script.



    Reject a register if any earlier definition is not the same literal. Restores



    after copying v0 do not affect the proof. Calls preserve s0..s7 by the ABI.



    """



    defs={};values=[]



    for w in words:



        op=w>>26;rs=w>>21&31;rt=w>>16&31;rd=w>>11&31;fn=w&63



        if op==0 and fn in (33,45) and rd==2 and 16<=rs<=23 and rt==0:



            vv=defs.get(rs,[])



            if not vv or any(x is None or x!=vv[0] for x in vv):return None



            values.append(vv[0])



        dest=None;value=None



        if op==0 and fn not in (8,9,24,25,26,27):dest=rd



        elif op in (8,9,10,11,12,13,14,15,24,25,26,27,30,32,33,35,36,37,39,55):dest=rt



        if dest is not None and 16<=dest<=23:



            if op==9 and rs==0:value=(w&65535) if (w&65535)<32768 else (w&65535)-65536



            defs.setdefault(dest,[]).append(value)



    return values[0] if values and len(set(values))==1 and 1<=values[0]<=64 else None







def native_lengths(elf, symbols):



    """Read constant set_next_seqadr arguments in the original EE handlers."""



    result = {}



    call = (3 << 26) | (0x7325a0 >> 2)



    for row in symbols:



        name = row['name']



        if not re.fullmatch(r'MESS_code[0-9a-f]{2}(?:[0-9a-f]{2})?', name):



            continue



        start = int(row['address']); size = int(row['size'])



        words = struct.unpack('<'+'I'*(size//4), elf[384+start-0x700000:384+start-0x700000+size])



        sizes = set()



        for i, w in enumerate(words):



            if w != call: continue



            for j in (i-1, i+1):



                if 0 <= j < len(words) and words[j] >> 16 == 0x2404:



                    sizes.add(words[j] & 65535)



        if len(sizes) == 1:



            result[bytes.fromhex(name[9:])] = sizes.pop()



        if name.startswith(('MESS_code0f','MESS_code0e')) and len(name)==13:



            length=returned_length(words)



            if length is not None:result[bytes.fromhex(name[9:])]=length



    # Some bytecode opcodes are aliases of one handler (1210..121f, etc.).



    # Resolve the actual EE dispatch arrays rather than guessing alias lengths.



    byname={q['name']:q for q in symbols}



    byaddr={int(q['address']):q['name'] for q in symbols if q['name'].startswith('MESS_code')}



    for name,row in byname.items():



        match=re.fullmatch(r'mess_func_tbl_code([0-9a-f]{2})',name)



        if not match:continue



        table=int(row['address']);size=int(row['size']);assert size%4==0



        for v in range(size//4):



            target=struct.unpack_from('<I',elf,384+table-0x700000+v*4)[0]



            if target not in byaddr:continue



            canonical=bytes.fromhex(byaddr[target][9:])



            if canonical in result:result[bytes.fromhex(match[1]+f'{v:02x}')]=result[canonical]



    # These handlers return/jump, or delegate without a constant local increment.



    result.update({b'\x00':1,b'\x01':1,b'\x02':5,b'\x03':5,b'\x04':5,



                   b'\x05':5,b'\x06':5,b'\x07':5,b'\x22':1,b'\x23':1,



                   b'\x16\x06':8,b'\x16\x07':8,b'\x0e\x10':2,



                   b'\x16\x09':2,b'\x16\x14':7,b'\x11\x32':2,



                   b'\x16\x0e':3,b'\x16\x0f':3,b'\x17\x29':3,



                   b'\x10\x24':6,b'\x10\x25':2})



    return result







def graph(data, lengths, text_at, extra_roots=()):



    """Entry table -> instruction boundaries -> validated call/branch targets.







    A text call is opaque, including its original trailing 01. Unknown opcode



    lengths and dynamic targets terminate that edge instead of guessing.



    """



    n = struct.unpack_from('<I', data)[0]



    roots = []



    if 0 < n <= 1024 and 4+n*4 <= len(data):



        vals = struct.unpack_from('<'+'I'*n, data, 4)



        if all(4+n*4 <= x < len(data) for x in vals):



            roots = list(vals)



            # _get_mess_adr (732BC4..732BD0) indexes base+4+index*4;



            # it never uses word0 as the extent of this dispatch arena. Some



            # MES files expose only 3 primary entries there, followed by hundreds



            # of callable slots. Admit the entire arena only when aligned dword



            # pointers tile exactly up to the earliest pointed-to byte.



            end=min(vals);p=4+n*4;extra=[]



            while p+4<=end:



                v=struct.unpack_from('<I',data,p)[0]



                if v==0:

                    p+=4;continue # Null dispatch slots are valid; require exact arena tiling below.

                if not p+4<=v<len(data):break



                extra.append(v);end=min(end,v);p+=4



            if p==end or (end==((p+15)&~15) and end-p<=15 and not any(data[p:end])):roots.extend(extra)



            roots=list(dict.fromkeys(roots))



    # Some indexed dispatch tables are in the function body, not the header.

    # Require >=4 aligned pointers to CALL-local/RETURN wrappers; random numeric

    # fields or raw string tables are NOT script-entry evidence.

    arena=0

    while arena+16<=len(data):

        end=arena;stubs=[]

        while end+4<=len(data):

            t=struct.unpack_from('<I',data,end)[0]

            if not 4<=t<=len(data)-6 or data[t]!=3 or data[t+5]!=1:break

            dest=struct.unpack_from('<I',data,t+1)[0]

            if not 4<=dest<len(data) or data[dest]<0x27:break

            stubs.append(t);end+=4

        if len(stubs)>=4 and len(set(stubs))>=4:roots.extend(stubs)

        arena=max(arena+4,end)

    roots=list(dict.fromkeys(roots+list(extra_roots)))

    queue = list(roots); nodes = {}; unknown = collections.Counter()



    while queue:



        p = queue.pop()



        if p in nodes or not 0 <= p < len(data): continue



        op = data[p:p+1]



        if op[0] >= 0x27:



            size=1 if op[0]>=0x30 else 2



            if p+size>len(data):continue



            nodes[p]=dict(key=b'FONT',size=size,target=None,edges=[p+size]);queue.append(p+size);continue



        key = data[p:p+2] if op in (b'\x0e',b'\x0f',b'\x10',b'\x11',b'\x12',b'\x13',b'\x14',b'\x15',b'\x16',b'\x17',b'\x18',b'\x19',b'\x1a',b'\x1b',b'\x1c',b'\x1d',b'\x1e',b'\x1f') else op



        size=lengths.get(key)



        if key==b'\x16\x05' and p+3<=len(data) and data[p+2]<=4:



            size=3 if data[p+2]==3 else 7



        if key in (b'\x10\x03',b'\x10\x25'):



            nodes[p]=dict(key=key,size=2,target=None,edges=[]);continue # event change deletes current object



        if size is None or p+size > len(data):



            unknown[key.hex()] += 1; continue



        edges=[]; target=None



        if op in (b'\x02',b'\x03',b'\x04',b'\x05',b'\x06',b'\x07'):



            target=struct.unpack_from('<I',data,p+1)[0]



            if target < len(data):

                record=text_at.get(target)

                text_end=target+int(record['byte_length']) if record else None

                terminal=bool(record and text_end<len(data) and data[text_end] in (0,1))

                # A string ending at 22/another control is only the first span

                # of a script function, NOT an opaque returning text call.

                edges.append(target) # Parse FONT/01 too, so callers establish actual text boundaries.



            if op != b'\x02': edges.append(p+size)



        elif key==b'\x10\x00':

            # MESS_code1000 -> set_event_work stores its first descriptor; the

            # deferred event loader later resolves it as the new script entry.

            # Only plain local descriptors are admitted, never dynamic flags.

            target=struct.unpack_from('<I',data,p+2)[0]

            if 4<=target<len(data):edges.append(target)

            edges.append(p+size)



        elif key==b'\x10\x24':



            target=struct.unpack_from('<I',data,p+2)[0]



            if target<len(data) and target not in text_at:edges.append(target)



        elif op not in (b'\x00',b'\x01') and key!=b'\x11\x32': edges.append(p+size)



        nodes[p]=dict(key=key,size=size,target=target,edges=edges)



        queue.extend(edges)



    return nodes, roots, dict(unknown)







def columns(data, nodes, roots, spans, span_overrides=None, numeric_pitch=None):



    """Propagate original/new cursors through proven instruction boundaries.







    Stop width inference across an unanalysed helper, window selection, clear,



    newline, numeric conversion, or a dynamic work-register operation. Constants



    are patched only for native pixel anchors 12 20 <u16> 1f 04. Grid anchors



    and unknown cases are reported rather than rounded or guessed.



    """



    span_overrides=span_overrides or {}; edits={}; pending=[]; seen=set(); limits=collections.Counter(); blocked=[]



    # Every routine entry is also visited, so shared UI functions are covered.



    entries=set(roots)



    for node in nodes.values():



        if node['key'] in (b'\x03',b'\x05',b'\x07') and node['target'] in nodes: entries.add(node['target'])



    pending.extend((p,None,None,None) for p in entries)



    def numeric_field(p):



        for _ in range(12):



            q=nodes.get(p)



            if q is None:return None



            if q['key']==b'\x16\x07':return data[p+2],data[p+7]



            if q['key'][:1]!=b'\x12' and q['key']!=b'\x16\x10':return None



            p+=q['size']



        return None



    while pending:



        p,old,new,work=pending.pop(); state=(p,old,new,work)



        if state in seen or p not in nodes: continue



        seen.add(state);limits[p]+=1



        if limits[p]>64: blocked.append(dict(offset=p,reason='path_state_limit'));continue



        node=nodes[p];key=node['key'];end=p+node['size'];target=node['target']



        if key in (b'\x03',b'\x05',b'\x07'):



            if target in spans:



                ow,nw=spans[target];nw=span_overrides.get(p,nw)



                if old is not None: old+=ow;new+=nw



            else:old=new=None



            work=None



        elif key == b'\x12\x20':work=(p+2,struct.unpack_from('<H',data,p+2)[0])



        elif key in (b'\x1f\x04',b'\x1f\x00'):



            anchor=work[1] if key==b'\x1f\x04' and work else data[p+2]*24 if key==b'\x1f\x00' else None



            if anchor is None:old=new=None



            else:



                want=anchor



                numeric=numeric_field(end) if numeric_pitch is not None else None



                digits,number_mode=numeric if numeric else (None,None)



                kind='text_column'



                if old is not None:



                    # An explicit backwards origin may be an intentional overlay.



                    # Growth protection is inferred only for originally forward columns.



                    if digits is not None and 1<=digits<=20 and old<=anchor+24*digits and new>old:



                        # 1607 positions text at anchor + 24*n - actual_width.



                        # A numeric field's anchor is NOT the leftmost digit.



                        pitch=numeric_pitch[number_mode] if isinstance(numeric_pitch,dict) and number_mode in numeric_pitch else numeric_pitch



                        if not isinstance(pitch,int):blocked.append(dict(offset=p,reason='unknown_numeric_mode'));pitch=24



                        want=max(anchor,new+8-digits*(24-pitch));kind='numeric_right_aligned'



                    elif anchor >= old-2 and new>old:



                        want=max(anchor,new+max(8,anchor-old))



                    elif new>anchor:blocked.append(dict(offset=p,reason='original_backward_or_overlapping_anchor',anchor=anchor,old_cursor=old,new_cursor=new))



                if want!=anchor:



                    if key==b'\x1f\x04' and work and want<=511:



                        field=work[0];q=edits.setdefault(field,dict(field=field,old=anchor,new=want,anchor=p,kind=kind))



                        if want>=q['new']:



                            q.update(new=want,original_cursor=old,translated_cursor=new)



                            if kind=='numeric_right_aligned':q.update(digits=digits,max_digit_pitch=pitch,minimum_gap=want+digits*(24-pitch)-new)



                            else:q.update(minimum_gap=want-new)



                    else:blocked.append(dict(offset=p,reason='grid_anchor_requires_callsite_rewrite',old=anchor,required=want))



                if work and work[0] in edits:want=max(want,edits[work[0]]['new'])



                old,new=anchor,want



            work=None



        elif key in (b'\x22',b'\x23'):



            old=new=0;work=None



        elif key in (b'\x16\x02',b'\x16\x04',b'\x16\x11',b'\x16\x0c',b'\x11\x32',b'\x11\x33',b'\x16\x14',b'\x16\x35',b'\x16\x36'):



            old=new=None;work=None



        elif key in (b'\x16\x06',b'\x16\x07'):



            # Digits are runtime values; their right edge remains n*24 native units.



            old=new=None;work=None



        elif key[:1]==b'\x16' and key!=b'\x16\x10':



            # Remaining window/object operations may change a render mode or



            # select a different text object. Do not carry a guessed cursor.



            old=new=None;work=None



        elif key==b'FONT':old=new=None



        elif key[:1] in (b'\x0e',b'\x0f',b'\x12',b'\x13'):work=None



        edges=node['edges']



        if key in (b'\x03',b'\x05',b'\x07'):edges=[end] # A helper body is analysed independently.



        for dest in edges:pending.append((dest,old,new,work))



    return sorted(edits.values(),key=lambda q:q['field']),blocked,dict(states=len(seen),instructions=len(nodes))







def apply_columns(data, edits):



    result=bytearray(data)



    for edit in edits:



        p=edit['field'];assert struct.unpack_from('<H',result,p)[0]==edit['old']



        assert result[p-2:p]==b'\x12\x20' and result[p+2:p+4]==b'\x1f\x04'



        struct.pack_into('<H',result,p,edit['new'])



    return result







def space(pixels):



    """Layout-only relative spacing. No font slot, glyph, or work register used."""



    if not 1 <= pixels <= 511: raise ValueError(pixels)



    return b'\x27\xfd'+pixels.to_bytes(2,'big')







def continuous_after(p,data,nodes,text_at,trail=frozenset(),depth=0):



    """Kinds of first output after a label; gaps are useful only before glyphs.







    Reject paths which position independently, clear/change windows, return to an



    unknown caller, or wait on dynamic text. Never pad an entire line-end message.



    """



    if depth>80 or p in trail or p not in nodes:return {'unknown'}



    n=nodes[p];k=n['key'];end=p+n['size'];trail=trail|{p}



    if k==b'FONT':return {'newline'} if data[p:p+2]==b'\x27\x80' else {'glyph'}



    if k in (b'\x00',b'\x01'):return {'return'}



    if k[:1]==b'\x1f' or k in (b'\x22',b'\x23'):return {'position_or_line'}



    if k in (b'\x11\x32',b'\x11\x33'):return {'dynamic'}



    if k[:1]==b'\x16' and k!=b'\x16\x10':return {'window_or_number'}



    if k in (b'\x03',b'\x05',b'\x07'):



        target=n['target']



        if target in text_at:out={'glyph'}



        else:out=continuous_after(target,data,nodes,text_at,trail,depth+1)



        if 'return' in out:



            out=(out-{'return'})|continuous_after(end,data,nodes,text_at,trail,depth+1)



        if k!=b'\x03':out|=continuous_after(end,data,nodes,text_at,trail,depth+1)



        return out



    out=set()



    for edge in n['edges']:out|=continuous_after(edge,data,nodes,text_at,trail,depth+1)



    return out or {'unknown'}











def conditional_gap_sites(parent,data,nodes,roots,text_at):



    """Place a gap on glyph-producing branches, never on the other branches.







    The parent must dominate every admitted prefix node: no alternative entry,



    external predecessor, or shared helper is allowed. This is deliberately more



    restrictive than byte-pattern matching and does not alter branch decisions.



    """



    start=parent+nodes[parent]['size'];pending=[start];prefix=set();glyphs=set()



    while pending:



        p=pending.pop()



        if p in prefix or p in glyphs:continue



        n=nodes.get(p)



        if n is None:return []



        k=n['key']



        if k==b'FONT':



            if data[p:p+2]!=b'\x27\x80':glyphs.add(p)



            continue



        if k in (b'\x00',b'\x01',b'\x22',b'\x23') or k[:1]==b'\x1f':continue



        if k[:1]==b'\x16' and k!=b'\x16\x10':continue



        if k in (b'\x11\x32',b'\x11\x33'):return []



        if k in (b'\x03',b'\x05',b'\x07'):



            if k==b'\x03' and n['target'] in text_at:glyphs.add(p);continue



            return []



        prefix.add(p);pending.extend(n['edges'])



        if len(prefix)>512:return []



    if not glyphs:return []



    region=prefix|glyphs



    # Discard the branch which reaches a window change without emitting text.



    # Its join point may legitimately have predecessors AFTER the first glyph.



    predecessors=collections.defaultdict(set)



    for p in region:



        for edge in nodes[p]['edges']:



            if edge in region:predecessors[edge].add(p)



    needed=set(glyphs);queue=list(glyphs)



    while queue:



        p=queue.pop()



        for prev in predecessors[p]-needed:needed.add(prev);queue.append(prev)



    region=needed



    if region&set(roots):return []



    for p,n in nodes.items():



        for edge in n['edges']:



            if edge in region and p not in region and p!=parent:return []



    plans=[]



    for first in sorted(glyphs):



        p=first;covered=[]



        while p-first<5:



            n=nodes.get(p)



            if n is None:return []



            k=n['key']



            if not (k==b'FONT' and data[p:p+2]!=b'\x27\x80' or k==b'\x03' and n['target'] in text_at):return []



            covered.append(p);p+=n['size']



        # No branch/root may land in the overwritten instruction span.



        if any(first<x<p for x in roots):return []



        for prev,n in nodes.items():



            if any(first<edge<p for edge in n['edges']) and prev not in covered:return []



        plans.append(dict(entry=first,end=p,source_hex=data[first:p].hex(),parent_call=parent))



    return plans







def flow_padding(raw, encoded, old_width, new_width, old_indent=0, new_indent=0):



    """Preserve proven UI flow spans and left indentation independently of ink."""



    lead=max(0,old_indent-new_indent)



    if isinstance(old_width,dict):



        tail=max(0,max(old_width[s]-new_width[s]-lead for s in old_width))



    else:tail=max(0,old_width-new_width-lead)



    if max(lead,tail)>511:raise ValueError('Layout span exceeds native 9-bit coordinate')



    return (space(lead) if lead else b'')+encoded+(space(tail) if tail else b''),lead,tail







def apply_plan(resources, column_edits, flow_edits, encode):



    """Apply to disposable resource copies, after the ordinary text importer.







    Required resource keys: original/data; data is a bytearray. Per-call payloads



    preserve address-specific translations and shared table consumers. This does



    not change ELF/ISO, loader tables, or any source translation.



    """



    results=[];cache={}



    for edit in column_edits:



        key=edit['resource'];r=resources[key];p=edit['field']



        assert r['original'][p-2:p+4]==b'\x12\x20'+struct.pack('<H',edit['old'])+b'\x1f\x04'



        assert r['data'][p-2:p+4]==r['original'][p-2:p+4],('Modified code at layout anchor',key,p)



        struct.pack_into('<H',r['data'],p,edit['new'])



        results.append(dict(resource=key,kind='column',field=p,old=edit['old'],new=edit['new']))



    for edit in flow_edits:



        key=edit['resource'];r=resources[key];p=edit['call_offset']



        assert r['original'][p]==3 and r['data'][p]==3



        assert struct.unpack_from('<I',r['original'],p+1)[0]==edit['source_target']



        raw=encode(edit['translation'])



        lead,tail=edit['leading_pixels'],edit['trailing_pixels']



        payload=(space(lead) if lead else b'')+raw+(space(tail) if tail else b'')+b'\x01'



        ident=(key,payload)



        if ident not in cache:



            dest=len(r['data']);assert dest+len(payload)<=0xfffff



            r['data'].extend(payload);cache[ident]=dest



        dest=cache[ident];struct.pack_into('<I',r['data'],p+1,dest)



        assert r['data'][dest:dest+len(payload)]==payload



        results.append(dict(resource=key,kind='flow',call=p,new_target=dest,payload_bytes=len(payload)))



    return results











def apply_font_scale_edits(resources, edits):



    """Scoped 32-bit float immediates; never resample a glyph or alter a CSV."""



    applied=[]



    for edit in edits:



        r=resources[edit['resource']];p=edit['field']



        original=bytes.fromhex(edit['old_hex']);new=bytes.fromhex(edit['new_hex'])



        assert len(original)==len(new)==4



        assert r['original'][p-2:p+6]==b'\x12\x30'+original+b'\x16\x15'



        assert r['data'][p-2:p+6]==r['original'][p-2:p+6]



        r['data'][p:p+4]=new



        applied.append(dict(resource=edit['resource'],field=p,old=struct.unpack('<f',original)[0],new=struct.unpack('<f',new)[0]))



    return applied











def apply_conditional_gaps(resources,edits):



    applied=[]



    for edit in edits:



        r=resources[edit['resource']];p=edit['entry'];end=edit['end']



        assert r['original'][p:end]==bytes.fromhex(edit['source_hex'])



        # Copy AFTER text relocation so the original call operands remain valid.



        copied=bytes(r['data'][p:end]);dest=len(r['data'])



        payload=space(edit['pixels'])+copied+b'\x02'+struct.pack('<I',end)



        assert dest+len(payload)<=0xfffff



        r['data'].extend(payload);r['data'][p:p+5]=b'\x02'+struct.pack('<I',dest)



        assert r['data'][dest+4:dest+4+len(copied)]==copied



        assert r['data'][dest+len(payload)-4:dest+len(payload)]==struct.pack('<I',end)



        applied.append(dict(resource=edit['resource'],kind='conditional_gap',entry=p,new_target=dest,pixels=edit['pixels'],copied_bytes=len(copied),return_to=end))



    return applied



