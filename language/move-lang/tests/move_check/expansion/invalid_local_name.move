module M {
    struct F has drop { No: u64 }

    fun t(No: u64) {
        No;
    }

    fun t2() {
        let No;
        No = 100;
    }

    fun t3() {
        let No = 100;
        F { No };
    }

    fun t4() {
        let _No;
    }

}
