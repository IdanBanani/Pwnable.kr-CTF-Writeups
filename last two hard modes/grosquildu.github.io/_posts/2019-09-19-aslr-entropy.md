---
layout: post
title: ASLR entropy
category: exploitation
tags: [pwn]
use_math: false
---

tldr; simple code for ASLR entropy measurements

For exploit development it may be necessary to do some brute-forcing of the target binary address space.
Since I couldn't find any short overwiew of ASLR entropy (which bits are constant etc), decided to write simple code to test it.

[The code is here.]({{ "/assets/posts/2019-09-19-aslr-entropy/test_aslr.tar.gz" }})

And here goes the results for 64 bit app:

```
# first line - "?" are random bits
# the plot   - Y axis represents probability of nth bit being "1"

./aslr_stuff » time ./test_aslr ./main 50000
[+] Test runs performed: 50000
[+] test runs failed:    0

page type -     const bits                                              no. of random bits
code      -     00000000000000000?0?0???????????????????????????????000000000000     33/64
               |                 x x x                                          
               |                                                                
               |                                                                
               |                       x                                        
               |                        xx  x x  x x xxx    xx xx x             
               |                          xx x xx x x   xxxx  x  x x            
               |                      x                                         
               |                                                                
               |                                                                
            ---|xxxxxxxxxxxxxxxxx-x-x-------------------------------xxxxxxxxxxxx---
               |

[heap]    -     0000000000000000010101??????????????????????????????000000000000     30/64
               |                 x x x                                          
               |                                                                
               |                                                                
               |                       x                                        
               |                        xx  x x  x x           x xxx            
               |                          xx x xx x xxxxxxxxxxx x               
               |                      x                                         
               |                                                                
               |                                                                
            ---|xxxxxxxxxxxxxxxxx-x-x-------------------------------xxxxxxxxxxxx---
               |

libc      -     00000000000000000111111?????????????????????????????000000000000     29/64
               |                 xxxxxxx                                        
               |                                                                
               |                                                                
               |                                                                
               |                        x  x x x  xxx       xx xx               
               |                         xx x x xx   xxxxxxx  x  xxx            
               |                                                                
               |                                                                
               |                                                                
            ---|xxxxxxxxxxxxxxxxx-----------------------------------xxxxxxxxxxxx---
               |

ld        -     00000000000000000111111?????????????????????????????000000000000     29/64
               |                 xxxxxxx                                        
               |                                                                
               |                                                                
               |                                                                
               |                        x  x x x  xxx    xx xxx x xx            
               |                         xx x x xx   xxxx  x   x x              
               |                                                                
               |                                                                
               |                                                                
            ---|xxxxxxxxxxxxxxxxx-----------------------------------xxxxxxxxxxxx---
               |

[stack]   -     000000000000000001111111111111??????????????????????000000000000     22/64
               |                 xxxxxxxxxxxxx                                  
               |                                                                
               |                                                                
               |                                                                
               |                               xx   x   x x    xxxxx            
               |                              x  xxx xxx x xxxx                 
               |                                                                
               |                                                                
               |                                                                
            ---|xxxxxxxxxxxxxxxxx-----------------------------------xxxxxxxxxxxx---
               |

[vdso]    -     00000000000000000111111?????????????????????????????000000000000     29/64
               |                 xxxxxxxxxxxxx                                  
               |                                           x                    
               |                                                                
               |                                            xx                  
               |                               xxx  x   x x   xxxx x            
               |                              x   xx xxx x        x             
               |                                                                
               |                                                                
               |                                                                
            ---|xxxxxxxxxxxxxxxxx-----------------------------------xxxxxxxxxxxx---
               |

[vvar]    -     00000000000000000111111?????????????????????????????000000000000     29/64
               |                 xxxxxxxxxxxxx                                  
               |                                           x                    
               |                                                                
               |                                            xx                  
               |                               xxx  x   x     xxx x             
               |                              x   xx xxx xx      x x            
               |                                                                
               |                                                                
               |                                                                
            ---|xxxxxxxxxxxxxxxxx-----------------------------------xxxxxxxxxxxx---
               |



./test_aslr ./main 50000  29,50s user 10,70s system 59% cpu 1:07,81 total
```

And for 32-bit:

```
./aslr_stuff » time ./test_aslr ./main32 50000
[+] Test runs performed: 50000
[+] test runs failed:    0

page type -     const bits              no. of random bits
code      -     0?0?0??00???????????000000000000     15/32
               | x x xx  x                      
               |                                
               |                                
               |           x                    
               |            xx    x             
               |              xxxx x            
               |          x                     
               |                                
               |                                
            ---|x-x-x--xx-----------xxxxxxxxxxxx---
               |

[heap]    -     ??01????????????????000000000000     18/32
               | x x                            
               |     xx                         
               |                                
               |                                
               |       x  xx                    
               |        xx  xxxxxxxx            
               |                                
               |                                
               |    x                           
            ---|x-x-----------------xxxxxxxxxxxx---
               |

libc      -     1??1011111??????????000000000000     12/32
               |xxxx xxxxx                      
               |                                
               |           x                    
               |                                
               |            xx xx x             
               |              x  x x            
               |                                
               |                                
               |                                
            ---|----x-----x---------xxxxxxxxxxxx---
               |

ld        -     1??1????????????????000000000000     18/32
               |xxxx xxxxxx                     
               |           x                    
               |                                
               |                                
               |            x   xx x            
               |             xxx  x             
               |                                
               |                                
               |                                
            ---|----x---------------xxxxxxxxxxxx---
               |

[stack]   -     ?111?111????????????000000000000     14/32
               |xxxxxxxxx                       
               |                                
               |                                
               |                                
               |            x x   x             
               |         xxx x xxx x            
               |                                
               |                                
               |                                
            ---|--------------------xxxxxxxxxxxx---
               |

[vdso]    -     ?1110111111?????????000000000000     10/32
               |xxxx xxxxxx                     
               |           x                    
               |                                
               |                                
               |            x   xxxx            
               |             xxx                
               |                                
               |                                
               |                                
            ---|----x---------------xxxxxxxxxxxx---
               |

[vvar]    -     ?1110111111?????????000000000000     10/32
               |xxxx xxxxxx                     
               |           x                    
               |                                
               |                                
               |            xx  x               
               |              xx xxx            
               |                                
               |                                
               |                                
            ---|----x---------------xxxxxxxxxxxx---
               |

./test_aslr ./main32 50000  29,62s user 10,42s system 59% cpu 1:07,77 total
```

The stack in 64-bit applications has only 22 bits of entropy. That gives 2^22 == 4194304 possible values.

Assuming that the stack is at least 0x25000 bytes big (default stack size on my system), we need to test only one of thirty-seven possible addresses (0x25000 / 0x1000 == 37). The amount of possibilities is reduced to about 113360 values.

How long it takes to brute-force stack address remotely?

```python
In [1]: 113360 / 60. / 60.
Out[1]: 31.488888888888887
```

Thirty-one and half hour with one execution per second speed.

It seems that if you can make ten executions in a second, then bruteforcing is feasible enough for ctf problems.
