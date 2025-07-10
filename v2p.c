#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */

#define PGD_SHIFT 39
#define PUD_SHIFT 30
#define PMD_SHIFT 21
#define PTE_SHIFT 12

#define PGD_OFFSET(addr) ((addr >> PGD_SHIFT) % 512) * 8
#define PUD_OFFSET(addr) ((addr >> PUD_SHIFT) % 512) * 8
#define PMD_OFFSET(addr) ((addr >> PMD_SHIFT) % 512) * 8
#define PTE_OFFSET(addr) ((addr >> PTE_SHIFT) % 512) * 8

/* Page size constants */
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

/* Mask to clear the 4th bit (used for write protection) */
#define MASK_4TH_BIT 0xFFFFFFFFFFFFFFF7

static void invalidate(u64 addr) 
{
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

int allocPFN(u64 *pgd_t)
{
    if (((*pgd_t) & 0x1) == 0)
    {
        *pgd_t = ((*pgd_t )| 0x1);  // Set present bit
        *pgd_t = ((*pgd_t) & 0xFFF); // Clear upper bits
        u64 temp = (u64) os_pfn_alloc(OS_PT_REG);
        if (!temp) return -1;
        *pgd_t =(( *pgd_t) | (temp << 12)); // Set PFN
    } 
}

int removePage(struct exec_context *current, struct vm_area* curr, u64 addr, u64 endAddr)
{
    // Align addresses to page boundaries
    addr = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    // Iterate over pages
    while(addr < endAddr)
    {
        // Calculate page table offsets
        u64 pgdOffset = PGD_OFFSET(addr);
        u64 pudOffset = PUD_OFFSET(addr);
        u64 pmdOffset = PMD_OFFSET(addr);
        u64 pteOffset = PTE_OFFSET(addr);

        // Get PGD entry
        u64 pgdAddr = (u64)osmap(current->pgd);
        u64* pgd_t = (u64 *)(pgdAddr + pgdOffset);

        // Check if PGD is present
        if (((*pgd_t) & 0x1) == 0) 
        {
            addr += PAGE_SIZE;
            continue;
        }

        // Get PUD entry
        u64 pudAddr = (u64)osmap((*pgd_t) >> PAGE_SHIFT);
        u64* pud_t = (u64 *)(pudAddr + pudOffset);

        // Check if PUD is present
        if (((*pud_t) & 0x1) == 0)
        {
            addr += PAGE_SIZE;
            continue;
        }

        // Get PMD entry
        u64 pmdAddr = (u64)osmap((*pud_t) >> PAGE_SHIFT);
        u64* pmd_t = (u64 *)(pmdAddr + pmdOffset);

        // Check if PMD is present
        if (((*pmd_t) & 0x1) == 0) 
        {
            addr += PAGE_SIZE;
            continue;
        }

        // Get PTE entry
        u64 pteAddr = (u64)osmap((*pmd_t) >> PAGE_SHIFT);
        u64* pte_t = (u64 *)(pteAddr + pteOffset);

        // Check if PTE is present
        if (((*pte_t) & 0x1) == 0) 
        {
            addr += PAGE_SIZE;
            continue;
        }

        // Get pfn
        u64 pfn = (*pte_t) >> PAGE_SHIFT;
        
        // Decrement reference count
        put_pfn(pfn);

        // Free pfn if refcount is 0
        if (get_pfn_refcount(pfn) == 0)
        {
            os_pfn_free(USER_REG, pfn);
        }

        // Clear pte
        (*pte_t) = 0x0;

        // Invalidate TLB entry
        invalidate(addr);
        
        addr += PAGE_SIZE;
    }
    return 0;
}

int changePage(struct exec_context *current, struct vm_area* curr, u64 addr, u64 endAddr, int prot)
{
    // Find length of segment to change
    int len = endAddr - addr;

    // Check if addr is within the vma
    if (addr >= curr->vm_end || addr < curr->vm_start)
    {
        return -1;
    }

    // Check if len is within the vma
    if (addr + len > curr->vm_end)
    {
        return -1;
    }

    // Check if len is aligned to page size
    if (len % PAGE_SIZE)
    {
        return -1;
    }
    
    // Find number of pages
    int pageCnt = len / PAGE_SIZE;

    // Iterate over pages
    for (int i = 0; i < pageCnt; i++)
    {
        // Find offsets
        u64 pgdOffset = PGD_OFFSET(addr);
        u64 pudOffset = PUD_OFFSET(addr);
        u64 pmdOffset = PMD_OFFSET(addr);
        u64 pteOffset = PTE_OFFSET(addr);
        
        u64 pgdAddr = (u64)osmap(current->pgd);
        u64* pgd_t = (u64 *)(pgdAddr + pgdOffset);

        // Check if pgd is present
        if (((*pgd_t) & 0x1) == 0)
        {
            continue;
        }

        // Check if 4th bit is 1
        if ((((*pgd_t) >> 4) & 0x1) == 0)
        {
            continue;
        }

        u64 pudAddr = (u64)osmap((*pgd_t) >> PAGE_SHIFT);
        u64* pud_t = (u64 *)(pudAddr + pudOffset);

        // Check if pud is present
        if (((*pud_t) & 0x1) == 0)
        {
            continue;
        }

        // Check if 4th bit is 1
        if ((((*pud_t) >> 4) & 0x1) == 0)
        {
            continue;
        }

        u64 pmdAddr = (u64)osmap((*pud_t) >> PAGE_SHIFT);
        u64* pmd_t = (u64 *)(pmdAddr + pmdOffset);

        // Check if pmd is present
        if (((*pmd_t) & 0x1) == 0)
        {
            continue;
        }

        // Check if 4th bit is 1
        if ((((*pmd_t) >> 4) & 0x1) == 0)
        {
            continue;
        }

        u64 pteAddr = (u64)osmap((*pmd_t) >> PAGE_SHIFT);
        u64* pte_t = (u64 *)(pteAddr + pteOffset);

        // Check if pte is present
        if (((*pte_t) & 0x1) == 0)
        {   
            continue;
        }

        // Check if 4th bit is 1
        if ((((*pte_t) >> 4) & 0x1) == 0)
        {
            continue;
        }

        // Get pfn
        u64 pfn = (*pte_t) >> PAGE_SHIFT;

        // Free pfn if refcount is 0
        if(get_pfn_refcount(pfn) != 1)
        {
            continue;
        }

        // Change page protection
        if (prot == (PROT_WRITE|PROT_READ)) *pte_t = (*pte_t | 0x8);
        else if (prot == PROT_READ) *pte_t = ((*pte_t) & MASK_4TH_BIT);

        invalidate(addr);

        addr += PAGE_SIZE;
    }

    return 0;
}

void mergeFragments(struct exec_context *current)
{
    struct vm_area* head = current->vm_area;
    struct vm_area* prev = head;
    struct vm_area* curr = head->vm_next;

    while(curr)
    {
        // Check if adjacent areas can be merged
        if(prev != head && curr->vm_start == prev->vm_end && curr->access_flags == prev->access_flags)
        {
            // Merge areas
            prev->vm_end = curr->vm_end;
            prev->vm_next = curr->vm_next;
            os_free(curr, sizeof(struct vm_area));
            stats->num_vm_area--;
            curr = prev->vm_next;
        }
        else
        {
            prev = curr;
            curr = curr->vm_next;
        }
    }
}

/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    // Validate input parameters
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE)) return -1;
    if (length <= 0) return -1;
    if (addr % PAGE_SIZE) return -1;

    // Get head of VMA list
    struct vm_area* VMA_Head = current->vm_area;

    if (!VMA_Head || VMA_Head->vm_start != MMAP_AREA_START || VMA_Head->vm_end != MMAP_AREA_START + PAGE_SIZE || VMA_Head->access_flags != 0)
    {
        if (!VMA_Head)
        {
            current->vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
            VMA_Head = current->vm_area;
        }
        VMA_Head->vm_start = MMAP_AREA_START;
        VMA_Head->vm_end = MMAP_AREA_START + PAGE_SIZE;
        VMA_Head->vm_next = NULL;
        VMA_Head->access_flags = 0;
        stats->num_vm_area = 1;
        return 0;
    }

    if (length % PAGE_SIZE) length = length + PAGE_SIZE - length % PAGE_SIZE;

    struct vm_area* curr_VMA = VMA_Head->vm_next;
    struct vm_area* prev_VMA = VMA_Head;

    while (curr_VMA)
    {
        if (prot != curr_VMA->access_flags)
        {
            if (addr <= curr_VMA->vm_start && addr + length >= curr_VMA->vm_end)
            {
                if(changePage(current, curr_VMA, curr_VMA->vm_start, curr_VMA->vm_end, prot) < 0) 
                    return -1;
                curr_VMA->access_flags = prot;
            }
            // Case 2: Region covers start of VMA
            else if (addr <= curr_VMA->vm_start && addr + length < curr_VMA->vm_end && 
                     addr + length > curr_VMA->vm_start)
            {
                if(changePage(current, curr_VMA, curr_VMA->vm_start, addr + length, prot) < 0) 
                    return -1;
                
                // Split VMA
                struct vm_area* new_vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                new_vm_area->vm_start = curr_VMA->vm_start;
                new_vm_area->vm_end = addr + length;
                new_vm_area->access_flags = prot;
                new_vm_area->vm_next = curr_VMA;

                curr_VMA->vm_start = addr + length;
                prev_VMA->vm_next = new_vm_area;

                stats->num_vm_area++;
                break;
            }
            // Case 3: Region covers end of VMA
            else if (addr > curr_VMA->vm_start && addr + length >= curr_VMA->vm_end && 
                     addr < curr_VMA->vm_end)
            {
                if(changePage(current, curr_VMA, addr, curr_VMA->vm_end, prot) < 0) 
                    return -1;
                
                // Split VMA
                struct vm_area* new_vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                new_vm_area->vm_start = addr;
                new_vm_area->vm_end = curr_VMA->vm_end;
                new_vm_area->access_flags = prot;
                new_vm_area->vm_next = curr_VMA->vm_next;

                curr_VMA->vm_end = addr;
                curr_VMA->vm_next = new_vm_area;
                stats->num_vm_area++;
            }
            // Case 4: Region is in middle of VMA
            else if (addr > curr_VMA->vm_start && addr + length < curr_VMA->vm_end)
            {
                if(changePage(current, curr_VMA, addr, addr + length, prot) < 0) 
                    return -1;
                
                // Split into three VMAs
                struct vm_area* vma2 = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                vma2->vm_start = addr + length;
                vma2->vm_end = curr_VMA->vm_end;
                vma2->access_flags = curr_VMA->access_flags;
                vma2->vm_next = curr_VMA->vm_next;

                struct vm_area* vma1 = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                vma1->vm_start = addr;
                vma1->vm_end = addr + length;
                vma1->access_flags = prot;
                vma1->vm_next = vma2;

                curr_VMA->vm_end = addr;
                curr_VMA->vm_next = vma1;

                stats->num_vm_area += 2;
                break;
            }
        }

        prev_VMA = curr_VMA;
        curr_VMA = curr_VMA->vm_next;
    }

    // Merge adjacent VMAs with same protection
    mergeFragments(current);
    return 0;
}


/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    // printk("Entering vm_area_map: addr=%d, length=%d, prot=%d, flags=%d\n", addr, length, prot, flags);
    
    // Input validation
    if(length <= 0 || length > 2 * 1024 * 1024)
    {
        // printk("Invalid length in mmap: %d\n", length);
        return -EINVAL;
    }
    if(prot != PROT_READ && prot != ( PROT_READ | PROT_WRITE ))
    {
        // printk("Invalid protection flags in mmap: %d\n", prot);
        return -EINVAL;
    }
    if (flags != 0 && flags != MAP_FIXED) 
    {
        // printk("Invalid flags in mmap: %d\n", flags);
        return -EINVAL;
    }
    if(addr % PAGE_SIZE != 0)
    {
        // printk("Invalid address in mmap: %d\n", addr);
        return -EINVAL;
    }

    // Find the head node
    struct vm_area *head = current->vm_area;
    // If no node , allocate one
    if(head == NULL)
    {
        head = os_alloc(sizeof(struct vm_area));
        if(head == NULL)
        {
            return -EINVAL;
        }
        head->vm_start = MMAP_AREA_START;
        head->vm_end = MMAP_AREA_START + PAGE_SIZE;
        head->access_flags = 0;
        head->vm_next = NULL;
        stats->num_vm_area = 1;

        current->vm_area = head;
    }

    // Align
    if (length % PAGE_SIZE)
    {
        length + PAGE_SIZE - length % PAGE_SIZE;
    }

    // Case 1 : flags are mapped but no addr
    if(!addr && (flags == MAP_FIXED))
    {
        return -EINVAL;
    }

    // Case 2 : Addr provided , use as hint
    else if(addr)
    {
        // Take 2 vma
        struct vm_area *prev = head;
        struct vm_area *curr = head->vm_next;
        // Check for vmas
        while(curr)
        {
            // Sub case 1 : Overlapped VMA's
            if((addr < curr->vm_end && addr >= curr->vm_start) || (addr < curr->vm_start && addr + length > curr->vm_start))
            {
                // If mapped flags, no need to do get out of function
                if(flags == MAP_FIXED)
                {
                    return -EINVAL;
                }
                // Else break out of the case we had found
                break;
            }

            // Before the vma
            if (addr < curr->vm_start && addr + length <= curr->vm_start)
            {
                //  if flags match and continous
                if (prev->vm_end == addr && prev->access_flags == prot && prev != current->vm_area)
                {
                    prev->vm_end = addr + length;
                    if(curr && addr + length == curr->vm_start && curr->access_flags == prot)
                    {
                        prev->vm_end = curr->vm_end;
                        prev->vm_next = curr->vm_next;
                        stats->num_vm_area--;
                        os_free(curr, sizeof(struct vm_area));
                    }
                    return addr;
                }

                // if lies with the curr vma
                // Truncate the start of vma , like extend it basically
                if(curr && addr + length == curr->vm_start && curr->access_flags == prot)
                {
                    curr->vm_start = addr;
                    return curr->vm_start;
                }

                // Else create a new one
                struct vm_area* dummy = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                dummy->vm_start = addr;
                dummy->vm_end = addr + length;
                dummy->access_flags = prot;
                
                // Update the list
                prev->vm_next = dummy;
                dummy->vm_next = curr;

                // Increase the counter
                stats->num_vm_area++;
                return addr;
            }

            prev = curr;
            curr = curr->vm_next;
        }

        // Nothing at the end
        if(!curr)
        {
            //  if flags match and continous
            if (prev->vm_end == addr && prev->access_flags == prot && prev != current->vm_area)
            {
                prev->vm_end = addr + length;
                return addr;
            }

            // Else create a new one
            struct vm_area* dummy = (struct vm_area*) os_alloc(sizeof(struct vm_area));
            dummy->vm_start = addr;
            dummy->vm_end = addr + length;
            dummy->access_flags = prot;
            
            // Update the list
            prev->vm_next = dummy;
            dummy->vm_next = NULL;

            // Increase the counter
            stats->num_vm_area++;
            return addr;
        }
    }

    struct vm_area* prev = head;
    struct vm_area* curr = prev->vm_next;

    while(curr)
    {
        // Can fit between
        if(curr->vm_start >= length + prev->vm_end)
        {
            //  if flags match and continous
            addr = prev->vm_end;
            if (prev->vm_end == addr && prev->access_flags == prot && prev != current->vm_area)
            {
                prev->vm_end = addr + length;
                if(curr && addr + length == curr->vm_start && curr->access_flags == prot)
                {
                    prev->vm_end = curr->vm_end;
                    prev->vm_next = curr->vm_next;
                    stats->num_vm_area--;
                    os_free(curr, sizeof(struct vm_area));
                }
                return addr;
            }

            // if lies with the curr vma
            // Truncate the start of vma , like extend it basically
            if(curr && addr + length == curr->vm_start && curr->access_flags == prot)
            {
                curr->vm_start = addr;
                return curr->vm_start;
            }

            // Else create a new one
            struct vm_area* dummy = (struct vm_area*) os_alloc(sizeof(struct vm_area));
            dummy->vm_start = addr;
            dummy->vm_end = addr + length;
            dummy->access_flags = prot;
            
            // Update the list
            prev->vm_next = dummy;
            dummy->vm_next = curr;

            // Increase the counter
            stats->num_vm_area++;
            return addr;
        }

        prev = curr;
        curr = curr->vm_next;
    }

    // Nothing at the end
    if(!curr)
    {
        addr = prev->vm_end;
        //  if flags match and continous
        if (prev->vm_end == addr && prev->access_flags == prot && prev != current->vm_area)
        {
            prev->vm_end = addr + length;
            return addr;
        }

        // Else create a new one
        struct vm_area* dummy = (struct vm_area*) os_alloc(sizeof(struct vm_area));
        dummy->vm_start = addr;
        dummy->vm_end = addr + length;
        dummy->access_flags = prot;
        
        // Update the list
        prev->vm_next = dummy;
        dummy->vm_next = NULL;

        // Increase the counter
        stats->num_vm_area++;
        return addr;
    }

    return -EINVAL;
}

/**
 * munmap system call implemenations
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    // Input validation
    if(length <= 0)
    {
        return -EINVAL;
    }

    // Align the length to page size
    if(length % PAGE_SIZE)
    {
        length = length + PAGE_SIZE - (length % PAGE_SIZE);
    }
    
    u64 end_addr = addr + length;

    // Access the nodes
    struct vm_area *head = current->vm_area;
    struct vm_area *curr = head->vm_next;
    struct vm_area *prev = head;

    // Find and modify VM areas that overlap with the unmap range
    while(curr)
    {
        struct vm_area *next = curr->vm_next;
        
        // Case 1: VM area completely within unmap range - remove it entirely
        if(addr <= curr->vm_start && end_addr >= curr->vm_end)
        {
            prev->vm_next = curr->vm_next;
            removePage(current, curr, curr->vm_start, curr->vm_end);
            os_free(curr, sizeof(struct vm_area));
            stats->num_vm_area--;
            curr = next;
            continue;
        }
        
        // Case 2: Unmap range covers the beginning of VM area
        else if(addr <= curr->vm_start && end_addr > curr->vm_start && end_addr < curr->vm_end)
        {
            removePage(current, curr, curr->vm_start, end_addr);
            curr->vm_start = end_addr;
            curr = next;
            continue;
        }
        
        // Case 3: Unmap range covers the end of VM area
        else if(addr > curr->vm_start && addr < curr->vm_end && end_addr >= curr->vm_end)
        {
            removePage(current, curr, addr, curr->vm_end);
            curr->vm_end = addr;
            curr = next;
            continue;
        }
        
        // Case 4: Unmap range in the middle of VM area - split into two
        else if(addr > curr->vm_start && end_addr < curr->vm_end)
        {
            struct vm_area *new_area = os_alloc(sizeof(struct vm_area));
            if(!new_area)
                return -ENOMEM;
                
            new_area->vm_start = end_addr;
            new_area->vm_end = curr->vm_end;
            new_area->access_flags = curr->access_flags;
            new_area->vm_next = curr->vm_next;
            
            curr->vm_end = addr;
            curr->vm_next = new_area;
            
            removePage(current, curr, addr, end_addr);
            stats->num_vm_area++;
            break;
        }
        
        prev = curr;
        curr = next;
    }

    // Merge adjacent VM areas with same access flags
    mergeFragments(current);
    
    return 0;
}

/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code) 
{
    // Get the curr VMA
    // printk("Entered page fault with addr %x and error code as %d\n",addr,error_code);
    struct vm_area *curr = current->vm_area->vm_next;

    // For all present VMA's
    while(curr)
    {
        // If addr lies in the vma
        if(addr >= curr->vm_start && addr < curr->vm_end)
        {
            // Invalid Access
            if (error_code == 7 && curr->access_flags == PROT_READ) return -1;
            if (error_code == 6 && curr->access_flags == PROT_READ) return -1;

            // Calculate offsets
            u64 pgdOffset = PGD_OFFSET(addr);
            u64 pudOffset = PUD_OFFSET(addr);
            u64 pmdOffset = PMD_OFFSET(addr);
            u64 pteOffset = PTE_OFFSET(addr);

            // Go to the pgd
            u64 pgdAddr = (u64)osmap(current->pgd);
            u64* pgd_t = (u64 *)(pgdAddr + pgdOffset);

            // Set 11000 to the pgd
            *pgd_t = ((*pgd_t) | 0b11000);

            int ret = allocPFN(pgd_t);
            if(ret == -1)
            {
                return ret;
            }

            // Go to the pud
            u64 pudAddr = (u64)osmap((*pgd_t) >> PAGE_SHIFT);
            u64* pud_t = (u64 *)(pudAddr + pudOffset);

            // Set 11000 to the pud
            *pud_t = ((*pud_t) | 0b11000);

            ret = allocPFN(pud_t);
            if(ret == -1)
            {
                return ret;
            }

            // Go to the pmd
            u64 pmdAddr = (u64)osmap((*pud_t) >> PAGE_SHIFT);
            u64* pmd_t = (u64 *)(pmdAddr + pmdOffset);

            // Set 11000 to the pud
            *pmd_t = ((*pmd_t) | 0b11000);

            ret = allocPFN(pmd_t);
            if(ret == -1)
            {
                return ret;
            }

            // Go to the pte
            u64 pteAddr = (u64)osmap((*pmd_t) >> PAGE_SHIFT);
            u64* pte_t = (u64 *)(pteAddr + pteOffset);

            // Set 10000 to the pte
            *pte_t = ((*pte_t) | 0b10000);

            // Mask the 4th bit as 0
            *pte_t = ((*pte_t) & MASK_4TH_BIT);

            // Check flags and set
            if(curr->access_flags == (PROT_READ | PROT_WRITE))
            {
                // Set 1000
                *pte_t = ((*pte_t) | 0b1000);
            }

            if (((*pte_t) & 0x1) == 0)
            {
                *pte_t = ((*pte_t )| 0x1);
                *pte_t = ((*pte_t) & 0xFFF);
                u64 temp = (u64) os_pfn_alloc(USER_REG);
                if (!temp) return -1;
                *pte_t =(( *pte_t) | (temp << 12));
            }

            // If write on read - COW
            if(error_code == 0x7)
            {
                return handle_cow_fault(current, addr, curr->access_flags);
            }

            return 1;
        }

        curr = curr->vm_next;
    }

    return -1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */

long do_cfork(){
    // printk("Entering do_cfork\n");
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* Do not modify above lines
     * 
     * */   
    /*--------------------- Your code [start]---------------*/
    

    /*--------------------- Your code [end] ----------------*/
    
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    // printk("Exiting do_cfork with pid=%d\n", pid);
    return pid;
}



/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    return 1;
}