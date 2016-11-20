#include "vm/frame.h"
#include "bitmap.h"
#include "threads/palloc.h"
#include "threads/synch.h"

/* A frame entry stores a single user page in the frame table
   to allow paging of user virtual memory. */
struct frame_entry
  {
    struct lock pin_lock;        /* Lock to prevent eviction. */
    struct list spte_list;       /* List of supplemental pte's for frame. */
    uint8_t *kpage;              /* Kernel virtual address for page. */
    size_t idx;                  /* Index into frame table. */
    struct frame_entry *next;    /* Circular linked list of frame_entries. */
  };

static struct lock frame_bitmap_lock;
static struct bitmap *frame_bitmap;
static struct frame_entry *frame_table;
static struct frame_entry *frame_clock_hand;

static struct frame_entry * frame_alloc_get_frame ();
static struct frame_entry * frame_evict ();
static void frame_pin (size_t);
static void frame_unpin (size_t);

/* Initializes the frame table to hold user pages. */
void
frame_init (size_t frame_cnt)
{
  lock_init (&frame_bitmap_lock);
  frame_bitmap = bitmap_create (frame_cnt);
  frame_table = calloc (frame_cnt, sizeof (struct frame_entry));
  int cur_frame_entry;
  for (cur_frame_entry = 0; cur_frame_entry < frame_cnt; 
       cur_frame_entry++)
    {
      lock_init (&frame_table [cur_frame_entry].pin_lock);
      list_init (&frame_table [cur_frame_entry].spte_list);
      frame_table [cur_frame_entry].idx = cur_frame_entry;
      frame_table [cur_frame_entry].next = &frame_table [cur_frame_entry];
    }
  frame_table [frame_cnt - 1].next = frame_table;
  frame_clock_hand = frame_table;
}

/* Destroy bitmap and free map table. */
void
frame_destroy ()
{
  if (frame_table != NULL)
    {
      bitmap_destroy (frame_bitmap);
      free (frame_table);
    }
}

/* Allocate a frame to place a user page in. If no frame is free, evict 
   a page to swap and write upage into its frame. If swap is full, 
   panic kernel.  */
static struct frame_entry *
frame_alloc_get_frame (struct list_elem *spte_lelem)
{
  size_t frame_idx;
  struct frame_entry frame_entry;

  /* No freeing or allocating during eviction. */
  lock_acquire (&frame_bitmap_lock);
  frame_idx = bitmap_scan_and_flip (frame_bitmap, 0, 1, false);
  /* If free frame is not found, evict a page from its frame. */
  if (frame_idx == BITMAP_ERROR)
    frame_entry = frame_evict ();
  else
    frame_entry = &frame_table [frame_idx];
  lock_release (&frame_bitmap_lock);
  return frame_entry;
}

/* Choose a frame to evict using a second-chance clock algorithm.
   Evict the frame and return its idx. */
static struct frame_entry *
frame_evict ()
{
  /* Cycle frame clock hand until we can evict. */
  while (true)
    {
      /* Give page another chance if it has been accessed. */
      
      frame_clock_hand = frame_clock_hand->next;
      return NULL;
    } 
  return NULL;
}

/* Pin a frame entry to prevent eviction. */
static void
frame_pin (size_t frame_idx)
{
  lock_acquire (&frame_table [frame_idx].pin_lock);
}

/* Unpin a frame entry to allow eviction. */
static void
frame_unpin (size_t frame_idx)
{
  lock_release (&frame_table [frame_idx].pin_lock);
}
