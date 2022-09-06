# Cairo Reverse [41 solves] [182 points] [First Blood 🩸]

![](https://i.imgur.com/aqEWrTx.png)

### Description :
```
Simple cairo reverse

starknet-compile 0.9.1

dist.zip

Author: ysc
```

Two files were given, the source code `contract.cairo`, and the compiled contract `contract_compiled.json`.

### Contract : 
```
# Declare this file as a StarkNet contract.
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

@view
func get_flag{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(t:felt) -> (res : felt):
    if t == /* CENSORED */:
        return (res=0x42414c534e7b6f032fa620b5c520ff47733c3723ebc79890c26af4 + t*t)
    else:
        return(res=0)
    end
end
```

One line is censored, so we have to reverse the compiled contract, and see what it will return as the flag.

After some quick googling, I found a tool for reversing cairo contracts : https://github.com/FuzzingLabs/thoth

Then just decompile the compiled contract with it : 
```
thoth -f contract_compiled.json -d -color
```

There is a hex value on the section for the `get_flag` function : 
```
@view func __main__.get_flag{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(t : felt) -> (res : felt)
    [AP] = [FP-3] + -0x1d6e61c2969f782ede8c3;    ap ++
    if [AP-1] == 0:
        [AP] =  [FP-3] * [FP-3];        ap ++
        [AP] = [FP-6];        ap ++
        [AP] = [FP-5];        ap ++
        [AP] = [FP-4];        ap ++
        [AP] = [AP-4] + 0x42414c534e7b6f032fa620b5c520ff47733c3723ebc79890c26af4;        ap ++
        return([ap-1])

    end
    [AP] = [FP-6];    ap ++
    [AP] = [FP-5];    ap ++
    [AP] = [FP-4];    ap ++
    # 0 -> 0x0
    [AP] = 0;    ap ++
    return([ap-1])
end
```

Finally, just get the flag with it : 
```python
>>> binascii.unhexlify(hex(-0x1d6e61c2969f782ede8c3*-0x1d6e61c2969f782ede8c3 + 0x42414c534e7b6f032fa620b5c520ff47733c3723ebc79890c26af4)[2:])
b'BALSN{read_data_from_cairo}
```