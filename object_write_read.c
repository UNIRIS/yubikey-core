#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<ctype.h>
#include<time.h>
#include<ykpiv/ykpiv.h>
#include<ykpiv/ykpiv-config.h>

#define MAX(a,b) (a) > (b) ? (a) : (b)
#define MIN(a, b) (a) < (b) ? (a) : (b)

#define CB_BUF_MAX_YK4      3072
#define CB_BUF_MAX          CB_BUF_MAX_YK4
#define CB_OBJ_MAX_YK4      (CB_BUF_MAX_YK4 - 9)
#define CB_OBJ_MAX          CB_OBJ_MAX_YK4

ykpiv_rc ykpiv_util_write_msroots(ykpiv_state *state, ykpiv_container *containers, size_t n_containers)
{
    uint8_t buf[CB_OBJ_MAX] = {0};
    size_t offset=0;
    size_t req_len=0;
    size_t data_len=n_containers * sizeof(ykpiv_container);

    // check if data and data_len are zero, this means that
  // we intend to delete the object
  if ((NULL == containers) || (0 == n_containers)) {

        // if either containers or n_containers are non-zero, return an error,
    // that we only delete strictly when both are set properly
    if ((NULL != containers) || (0 != n_containers)) {
      res = YKPIV_GENERIC_ERROR;
    }

  }
  else {
      res = ykpiv_save_object(state, YKPIV_OBJ_KEY_HISTORY, NULL, 0);
    }


    // encode object data for storage

    // calculate the required length of the encoded object
 
    req_len= 1 + (unsigned long)_ykpiv_set_length(buf, data_len) + data_len;

     if (req_len > _obj_size_max(state)) {
        res = YKPIV_SIZE_ERROR;
    
    }


buf[offset++] = 











}