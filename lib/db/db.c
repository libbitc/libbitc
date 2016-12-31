/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <bitc/db/db.h>                 // for db_handle, db_info, etc

#include <bitc/coredefs.h>              // for chain_find_by_netmagic, etc
#include <bitc/log.h>                   // for log_info, log_error, etc

#include <stdint.h>                     // for uint8_t
#include <stdio.h>                      // for NULL, snprintf
#include <string.h>                     // for memcmp, strlen
#include <unistd.h>                     // for sysconf, _SC_PAGESIZE

struct db_info dbinfo = {NULL,
	{[METADB] = {"metadb", (MDB_dbi) 0, false},
	[BLOCKDB] = {"blockdb", (MDB_dbi) 0, false},}
};

long get_pagesize()
{
#ifdef PAGESIZE
	return PAGESIZE;
#else
	long sz = sysconf(_SC_PAGESIZE);
	return sz;
#endif
}

bool metadb_init(const unsigned char *netmagic,
		const bu256_t *genesis_block)
{
	const struct chain_info *db_chain = chain_find_by_netmagic(netmagic);

	if (!db_chain)
		return false;

	int mdb_rc;
	MDB_txn *txn;
	MDB_val key_nm, key_gen, data_nm, data_gen;
	char db_filename[strlen(db_chain->name) + 4 + 1];
	enum metadb_key key_netmagic = NETMAGIC_KEY;
	enum metadb_key key_genesis = GENESIS_KEY;

	key_nm.mv_size = sizeof(enum metadb_key);
	key_nm.mv_data = &key_netmagic;
	key_gen.mv_size = sizeof(enum metadb_key);
	key_gen.mv_data = &key_genesis;

	snprintf(db_filename, sizeof(db_filename), "%s.mdb", db_chain->name);

	if ((mdb_rc = mdb_env_create(&dbinfo.env)) != MDB_SUCCESS) goto err_out;
	if ((mdb_rc = mdb_env_set_mapsize(dbinfo.env,(size_t)(((MAX_DB_SIZE - 1) | (get_pagesize() - 1)) + 1))) != MDB_SUCCESS) goto err_out;
	if ((mdb_rc = mdb_env_set_maxdbs(dbinfo.env, (MDB_dbi) MAX_NUM_DBS)) != MDB_SUCCESS) goto err_out;
	log_debug("db: Opening database file '%s'", db_filename);
	if ((mdb_rc = mdb_env_open(dbinfo.env, db_filename, MDB_NOSUBDIR, 0664)) != MDB_SUCCESS) goto err_out;
	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, 0, &txn)) != MDB_SUCCESS) goto err_out;

	if ((mdb_rc = mdb_dbi_open(txn, dbinfo.handle[METADB].name, MDB_INTEGERKEY, &dbinfo.handle[METADB].dbi)) == MDB_SUCCESS) {
		dbinfo.handle[METADB].open = true;
		log_info("db: Opening %s database", dbinfo.handle[METADB].name);

		if ((mdb_rc = mdb_get(txn, dbinfo.handle[METADB].dbi, &key_nm, &data_nm)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_get(txn, dbinfo.handle[METADB].dbi, &key_gen, &data_gen)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_close;

		if ((data_nm.mv_size != NETMAGIC_LEN) || (memcmp(data_nm.mv_data, netmagic, NETMAGIC_LEN))) {
			log_error("db: invalid netmagic");
			goto close_out;
		}

		if ((data_gen.mv_size != sizeof(bu256_t)) || (!bu256_equal(data_gen.mv_data, genesis_block))) {
			log_error("db: invalid genesis block");
			goto close_out;
		}

	} else if (mdb_rc == MDB_NOTFOUND) {
		log_info("db: Creating %s database", dbinfo.handle[METADB].name);

		data_nm.mv_size = NETMAGIC_LEN;
		data_nm.mv_data = (unsigned char *) netmagic;

		data_gen.mv_size = sizeof(bu256_t);
		data_gen.mv_data = (bu256_t *) genesis_block;

		if ((mdb_rc = mdb_dbi_open(txn, dbinfo.handle[METADB].name, MDB_CREATE, &dbinfo.handle[METADB].dbi)) != MDB_SUCCESS) goto err_abort;
		dbinfo.handle[METADB].open = true;

		if ((mdb_rc = mdb_put(txn, dbinfo.handle[METADB].dbi, &key_nm, &data_nm, MDB_NOOVERWRITE)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_put(txn, dbinfo.handle[METADB].dbi, &key_gen, &data_gen, MDB_NOOVERWRITE)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_close;
	} else goto err_abort;

	return true;

close_out:
	db_close();
	return false;
err_abort:
	mdb_txn_abort(txn);
err_close:
	db_close();
err_out:
	log_error("db: %s", mdb_strerror(mdb_rc));
	return false;
}

bool blockdb_init(void)
{
	int mdb_rc;
	MDB_txn *txn;

	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, 0, &txn)) != MDB_SUCCESS) goto err_out;

	log_info("db: Opening %s database", dbinfo.handle[BLOCKDB].name);
	if ((mdb_rc = mdb_dbi_open(txn, dbinfo.handle[BLOCKDB].name, MDB_CREATE, &dbinfo.handle[BLOCKDB].dbi)) != MDB_SUCCESS) goto err_abort;
	dbinfo.handle[BLOCKDB].open = true;

	if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_close;

	return true;

err_abort:
	mdb_txn_abort(txn);
err_close:
	db_close();
err_out:
	log_error("db: %s", mdb_strerror(mdb_rc));
	return false;
}

void db_close(void) {

	uint8_t i;
	log_info("db: Closing databases");

	for(i=METADB; i < MAX_NUM_DBS; i++) {
		if (dbinfo.handle[i].open) {
			mdb_dbi_close(dbinfo.env, dbinfo.handle[i].dbi);
			dbinfo.handle[i].open = false;
			log_debug("db: Closed %s database", dbinfo.handle[i].name);
		}
	}

	mdb_env_close(dbinfo.env);

	return;
}
