#ifndef __DISKID_H__
#define __DISKID_H__

int d2n_register(const diskid_t *diskid);
int d2n_nid(const diskid_t *diskid, nid_t *nid);
int d2n_init();
int disk2idx(const diskid_t *diskid, int *idx);
int chkid2coreid(const chkid_t *chkid, const nid_t *nid, coreid_t *coreid);
void disk2idx_online(const diskid_t *diskid, uint32_t idx);
void disk2idx_offline(const diskid_t *diskid);
int disk2idx_init();

#endif
