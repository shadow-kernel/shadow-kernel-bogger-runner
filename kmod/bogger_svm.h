/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_SVM_H
#define BOGGER_SVM_H
#include "bogger_types.h"

int  bogger_svm_check_support(void);
int  bogger_svm_enable(void);
int  bogger_svm_hsave_setup(void);
int  bogger_vmcb_init(void);
int  bogger_msr_bitmap_init(void);
void bogger_vmcb_reset(struct vmcb *vmcb);

#endif

