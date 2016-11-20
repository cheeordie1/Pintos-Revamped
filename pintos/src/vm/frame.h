#ifndef VM_FRAME_H
#define VM_FRAME_H

void frame_init (size_t);
void frame_destroy ();

void frame_alloc_get_page (uint8_t *);

#endif /* vm/frame.h */
