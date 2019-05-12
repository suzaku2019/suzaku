

#define DBG_SUBSYS S_LIBYLIBSKIPLIST

#include "sdfs_id.h"
#include "ylib.h"
#include "dbg.h"

int nid_cmp(const nid_t *keyid, const nid_t *dataid)
{
        int ret;

        if (keyid->id < dataid->id)
                ret = -1;
        else if (keyid->id > dataid->id)
                ret = 1;
        else {
                ret = 0;
        }

        return ret;
}

int coreid_cmp(const coreid_t *id1, const coreid_t *id2)
{
        int ret;
        
        ret = nid_cmp(&id1->nid, &id2->nid);
        if (ret)
                return ret;

        return id1->idx - id2->idx;
}

int verid64_cmp(const verid64_t *keyid, const verid64_t *dataid)
{
        int ret;

        if (keyid->id < dataid->id)
                ret = -1;
        else if (keyid->id > dataid->id)
                ret = 1;
        else {
                ret = 0;
        }

        return ret;
}


int verid64_void_cmp(const void *keyid, const void *dataid)
{

        return verid64_cmp((verid64_t *)keyid, (verid64_t *)dataid);
}

int nid_void_cmp(const void *keyid, const void *dataid)
{
        return nid_cmp((nid_t *)keyid, (nid_t *)dataid);
}
