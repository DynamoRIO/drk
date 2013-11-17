#ifndef __KVM_HYPERCALL_H_
#define __KVM_HYPERCALL_H_

#include <linux/kvm_host.h>

/* Arguments:
    nr: hypercall number
    a0 - a3: hypercall arguments
   These parameters correspond to the arguments passed by KVM's guest hypercall
   functions defined in <linux/kvm_para.h>

   The return value is placed in the guest's RAX register.
*/
typedef unsigned long(*kvm_hypercall_callback_t)(
                struct kvm_vcpu* vcpu,
                unsigned long nr,
                unsigned long a0,
                unsigned long a1,
                unsigned long a2,
                unsigned long a3); 

/* These functions are defined in arch/x86/kvm/x86.c. The function's return
 * value is placed in the guest's RAX register.
 */
void kvm_register_hypercall_callback(kvm_hypercall_callback_t callback);
void kvm_remove_hypercall_callback(kvm_hypercall_callback_t callback);

#endif
