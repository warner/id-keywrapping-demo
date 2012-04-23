
// this makes "s#" use Py_ssize_t instead of int
#define PY_SSIZE_T_CLEAN 1
#include "Python.h"
#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

static PyObject *ScryptError;
/* --------------------------------------------------------------------- */

#include "crypto_scrypt.h"
#include "scryptenc_cpuperf.h"

static PyObject *
scrypt_scrypt(PyObject *self, PyObject *args)
{
    const unsigned char *password, *salt;
    Py_ssize_t password_len, salt_len;
    Py_ssize_t N, r, p, dkLen;
    unsigned char *dk;
    PyObject *ret;

    if (!PyArg_ParseTuple(args, "s#s#nnnn", &password, &password_len,
                          &salt, &salt_len, &N, &r, &p, &dkLen))
        return NULL;
    dk = PyMem_Malloc(dkLen);
    if (!dk)
        return PyErr_NoMemory();
    // release the GIL during the CPU-heavy non-python work
    Py_BEGIN_ALLOW_THREADS
    crypto_scrypt(password, password_len, salt, salt_len, N, r, p, dk, dkLen);
    Py_END_ALLOW_THREADS
    ret = Py_BuildValue("s#", dk, dkLen);
    PyMem_Free(dk);
    return ret;
}

static PyObject *
scrypt_cpuperf(PyObject *self, PyObject *args)
{
    double ops_per_second;
    int rc;

    rc = scryptenc_cpuperf(&ops_per_second);
    if (rc != 0) {
        PyErr_SetString(ScryptError, "error running scryptenc_cpuperf");
        return NULL;
    }
    return Py_BuildValue("d", ops_per_second);
}

/* List of functions defined in the module */

static PyMethodDef scrypt_methods[] = {
    {"scrypt",  scrypt_scrypt,  METH_VARARGS, NULL},
    {"cpuperf",  scrypt_cpuperf,  METH_VARARGS, NULL},
    {NULL, NULL} /* sentinel */
};

PyDoc_STRVAR(module_doc,
"Low-level scrypt functions.");

/* Initialization function for the module (*must* be called init_scrypt) */

PyMODINIT_FUNC
init_scrypt(void)
{
    PyObject *m;

    /* Create the module and add the functions */
    m = Py_InitModule3("_scrypt", scrypt_methods, module_doc);
    if (m == NULL)
        return;

    /* Add some symbolic constants to the module */
    if (ScryptError == NULL) {
        ScryptError = PyErr_NewException("scrypt.ScryptError",
                                               NULL, NULL);
        if (ScryptError == NULL)
            return;
    }
    Py_INCREF(ScryptError);
    PyModule_AddObject(m, "ScryptError", ScryptError);
}
