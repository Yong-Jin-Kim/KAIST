#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "defs.h"
#include "x86.h"
#include "elf.h"

int
exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint argc, sz, sp, ustack[3+MAXARG+1];
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pde_t *pgdir, *oldpgdir;
  struct proc *curproc = myproc();

  begin_op();

  if((ip = namei(path)) == 0){
    end_op();
    cprintf("exec: fail\n");
    return -1;
  }
  ilock(ip);
  pgdir = 0;

  // Check ELF header
  if(readi(ip, (char*)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;
  if(elf.magic != ELF_MAGIC)
    goto bad;

  pde_t *pde;
  pte_t *pgtab;
  if((pgdir = (pde_t*)kalloc()) == 0)
    goto bad;
  memset(pgdir, 0, PGSIZE);
  for(i = PDX(KERNBASE); i < NPDENTRIES; i++){
    pde = &pgdir[i];
    pgtab = (pte_t*)P2V(PTE_ADDR(curproc->pgdir[i]));
    if(*pgtab & PTE_P){
      *pde = V2P(pgtab) | PTE_P | PTE_W;
    }
  }

  // Load program into memory.
  // initialize the page table using the information from the header of the ELF
  // but does not "map page table entries"
  //uint a;
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, (char*)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    //cprintf("[ph.vaddr 0x%x] [ph.off 0x%x] [ph.filesz 0x%x] [ph.memsz 0x%x]\n", ph.vaddr, ph.off, ph.filesz, ph.memsz);
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    sz = ph.vaddr + ph.memsz;
    curproc->text_end = ph.vaddr + ph.filesz;
    curproc->data_end = PGROUNDUP(ph.vaddr + ph.memsz);
    for(int j = 0; j <= PDX(ph.memsz); j++){
      pde = &pgdir[j];
      if((*pde & PTE_P) == 0){
	if((pgtab = (pte_t*)kalloc()) == 0)
	  goto bad;
	memset(pgtab, 0, PGSIZE);
	*pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
      }
    }
    //if((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
    //  goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    //if(loaduvm(pgdir, (char*)ph.vaddr, ip, ph.off, ph.filesz) < 0)
    //  goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  // Allocate two pages at the next page boundary.
  // Make the first inaccessible.  Use the second as the user stack.
  sz = PGROUNDUP(sz);
  if((sz = allocuvm(pgdir, sz, sz + 2*PGSIZE)) == 0)
    goto bad;
  clearpteu(pgdir, (char*)(sz - 2*PGSIZE));
  sp = sz;

  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp = (sp - (strlen(argv[argc]) + 1)) & ~3;
    if(copyout(pgdir, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[3+argc] = sp;
  }
  ustack[3+argc] = 0;

  ustack[0] = 0xffffffff;  // fake return PC
  ustack[1] = argc;
  ustack[2] = sp - (argc+1)*4;  // argv pointer

  sp -= (3+argc+1) * 4;
  if(copyout(pgdir, sp, ustack, (3+argc+1)*4) < 0)
    goto bad;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(curproc->name, last, sizeof(curproc->name));

  for(last=s=path; *s; s++);
  safestrcpy(curproc->filename, last, sizeof(curproc->filename));

  /*
  cprintf(curproc->name);
  cprintf("\n");
  cprintf(curproc->filename);
  cprintf("\n");
  */

  // Commit to the user image.
  oldpgdir = curproc->pgdir;
  curproc->pgdir = pgdir;
  curproc->sz = sz;
  curproc->tf->eip = elf.entry;  // main
  curproc->tf->esp = sp;
  switchuvm(curproc);
  freevm(oldpgdir);
  return 0;

 bad:
  if(pgdir)
    freevm(pgdir);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}
