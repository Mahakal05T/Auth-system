import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor

analytics_bp = Blueprint('analytics', __name__)

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return wrapper

@analytics_bp.route("/admin/analytics/overview", methods=["GET"])
@admin_required
def get_analytics_overview():
    """Retrieve executive performance analytics, revenue charts, and business metrics."""
    timeframe = request.args.get("timeframe", "30d").lower()
    
    now = datetime.utcnow()
    days_map = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
    num_days = days_map.get(timeframe, 30)

    start_date = (now - timedelta(days=num_days)) if timeframe != "all" else None

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Build date condition
        date_where = "WHERE o.created_at >= %s" if start_date else ""
        date_params = (start_date,) if start_date else ()

        # -------------------------------------------------------------
        # 1. Executive KPIs
        # -------------------------------------------------------------
        order_stats_sql = f"""
            SELECT 
                COUNT(*) as total_orders,
                SUM(CASE WHEN o.status != 'CANCELLED' THEN o.total_amount ELSE 0 END) as gross_revenue,
                SUM(CASE WHEN o.status != 'CANCELLED' THEN COALESCE(o.discount, 0) ELSE 0 END) as total_discounts,
                SUM(CASE WHEN o.status IN ('DELIVERED', 'COMPLETED') THEN 1 ELSE 0 END) as completed_orders,
                SUM(CASE WHEN o.status = 'CANCELLED' THEN 1 ELSE 0 END) as cancelled_orders,
                SUM(CASE WHEN o.status LIKE 'RETURN%' OR o.status = 'REFUNDED' THEN 1 ELSE 0 END) as returned_orders
            FROM orders o
            {date_where}
        """
        cursor.execute(order_stats_sql, date_params)
        order_stats = cursor.fetchone() or {}

        gross_rev = float(order_stats.get("gross_revenue") or 0.0)
        total_orders = int(order_stats.get("total_orders") or 0)
        completed_orders = int(order_stats.get("completed_orders") or 0)
        cancelled_orders = int(order_stats.get("cancelled_orders") or 0)
        returned_orders = int(order_stats.get("returned_orders") or 0)
        total_discounts = float(order_stats.get("total_discounts") or 0.0)

        # Total refunds in period
        refund_sql = f"""
            SELECT COALESCE(SUM(refund_amount), 0) as total_refunds
            FROM returns
            WHERE status = 'REFUNDED' {"AND created_at >= %s" if start_date else ""}
        """
        cursor.execute(refund_sql, date_params)
        total_refunds = float((cursor.fetchone() or {}).get("total_refunds") or 0.0)

        net_rev = max(0.0, round(gross_rev - total_refunds, 2))
        aov = round(gross_rev / max(1, total_orders - cancelled_orders), 2)

        # Units sold in period
        units_sql = f"""
            SELECT COALESCE(SUM(oi.quantity), 0) as total_units
            FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            WHERE o.status != 'CANCELLED' {"AND o.created_at >= %s" if start_date else ""}
        """
        cursor.execute(units_sql, date_params)
        total_units = int((cursor.fetchone() or {}).get("total_units") or 0)

        # Customer acquisition & repeat rate
        cust_sql = f"""
            SELECT 
                COUNT(DISTINCT o.user_id) as active_buyers,
                COUNT(DISTINCT u.id) as total_registered_customers
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id {"AND o.created_at >= %s" if start_date else ""}
        """
        cursor.execute(cust_sql, date_params)
        cust_row = cursor.fetchone() or {}
        active_buyers = int(cust_row.get("active_buyers") or 0)
        total_registered = int(cust_row.get("total_registered_customers") or 0)

        # Repeat customers (customers with 2+ orders ever)
        cursor.execute("""
            SELECT COUNT(*) as repeat_count FROM (
                SELECT user_id FROM orders WHERE status != 'CANCELLED' GROUP BY user_id HAVING COUNT(*) > 1
            ) t
        """)
        repeat_buyers = int((cursor.fetchone() or {}).get("repeat_count") or 0)
        repeat_rate = round((repeat_buyers / max(1, active_buyers)) * 100, 1)

        # Customer review sentiment (store average)
        cursor.execute("""
            SELECT COALESCE(AVG(rating), 5.0) as avg_rating, COUNT(*) as review_count
            FROM reviews WHERE status = 'approved' OR status IS NULL
        """)
        rev_row = cursor.fetchone() or {}
        avg_review_rating = round(float(rev_row.get("avg_rating") or 5.0), 2)
        total_reviews = int(rev_row.get("review_count") or 0)

        # -------------------------------------------------------------
        # 2. Daily Time-Series Chart Data
        # -------------------------------------------------------------
        timeseries_sql = f"""
            SELECT 
                DATE(o.created_at) as order_date,
                SUM(CASE WHEN o.status != 'CANCELLED' THEN o.total_amount ELSE 0 END) as daily_revenue,
                COUNT(*) as daily_orders
            FROM orders o
            {date_where}
            GROUP BY DATE(o.created_at)
            ORDER BY order_date ASC
        """
        cursor.execute(timeseries_sql, date_params)
        series_rows = cursor.fetchall()

        series_dict = {
            str(r["order_date"]): {
                "date": str(r["order_date"]),
                "revenue": float(r["daily_revenue"] or 0),
                "orders": int(r["daily_orders"] or 0)
            } for r in series_rows if r.get("order_date")
        }

        # If timeframe specified, populate continuous date array
        chart_series = []
        if start_date:
            days_to_fill = min(num_days, 60) # cap continuous chart points to 60 for clean UI
            step = max(1, num_days // 30) if num_days > 60 else 1
            curr = start_date.date()
            end_d = now.date()
            while curr <= end_d:
                key = curr.strftime("%Y-%m-%d")
                chart_series.append(series_dict.get(key, {
                    "date": key,
                    "label": curr.strftime("%b %d"),
                    "revenue": 0.0,
                    "orders": 0
                }))
                curr += timedelta(days=1)
        else:
            chart_series = list(series_dict.values())

        # Add readable short labels
        for pt in chart_series:
            try:
                dt = datetime.strptime(pt["date"], "%Y-%m-%d")
                pt["label"] = dt.strftime("%b %d")
            except Exception:
                pt["label"] = pt["date"]

        # -------------------------------------------------------------
        # 3. Category Sales Distribution
        # -------------------------------------------------------------
        cat_sql = f"""
            SELECT 
                c.id as category_id,
                c.name as category_name,
                COALESCE(SUM(oi.total), 0) as category_revenue,
                COALESCE(SUM(oi.quantity), 0) as units_sold
            FROM categories c
            LEFT JOIN products p ON p.category_id = c.id
            LEFT JOIN order_items oi ON oi.product_id = p.id
            LEFT JOIN orders o ON oi.order_id = o.id {"AND o.created_at >= %s" if start_date else ""}
            WHERE o.status IS NULL OR o.status != 'CANCELLED'
            GROUP BY c.id, c.name
            HAVING category_revenue > 0
            ORDER BY category_revenue DESC
        """
        cursor.execute(cat_sql, date_params)
        cat_rows = cursor.fetchall()

        category_distribution = []
        for cat in cat_rows:
            rev = float(cat["category_revenue"])
            share = round((rev / max(1.0, gross_rev)) * 100, 1)
            category_distribution.append({
                "category_id": cat["category_id"],
                "category_name": cat["category_name"],
                "revenue": rev,
                "units_sold": int(cat["units_sold"]),
                "share": share
            })

        # -------------------------------------------------------------
        # 4. Top Performing Products
        # -------------------------------------------------------------
        top_prod_sql = f"""
            SELECT 
                p.id as product_id,
                p.name as product_name,
                p.slug,
                p.price,
                p.stock,
                c.name as category_name,
                COALESCE(SUM(oi.quantity), 0) as units_sold,
                COALESCE(SUM(oi.total), 0) as revenue_generated,
                (
                    SELECT pi.image_url FROM product_images pi 
                    WHERE pi.product_id = p.id 
                    ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                ) as image_url
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            JOIN order_items oi ON oi.product_id = p.id
            JOIN orders o ON oi.order_id = o.id
            WHERE o.status != 'CANCELLED' {"AND o.created_at >= %s" if start_date else ""}
            GROUP BY p.id, p.name, p.slug, p.price, p.stock, c.name
            ORDER BY revenue_generated DESC
            LIMIT 6
        """
        cursor.execute(top_prod_sql, date_params)
        top_prods = cursor.fetchall()
        top_products = []
        for tp in top_prods:
            top_products.append({
                "id": tp["product_id"],
                "name": tp["product_name"],
                "slug": tp["slug"],
                "price": float(tp["price"]),
                "stock": int(tp["stock"]),
                "category": tp.get("category_name") or "General",
                "units_sold": int(tp["units_sold"]),
                "revenue": float(tp["revenue_generated"]),
                "image": tp.get("image_url") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80"
            })

        # -------------------------------------------------------------
        # 5. Payment Methods Breakdown
        # -------------------------------------------------------------
        pay_sql = f"""
            SELECT 
                o.payment_method,
                COUNT(*) as usage_count,
                SUM(o.total_amount) as total_volume
            FROM orders o
            WHERE o.status != 'CANCELLED' {"AND o.created_at >= %s" if start_date else ""}
            GROUP BY o.payment_method
            ORDER BY total_volume DESC
        """
        cursor.execute(pay_sql, date_params)
        pay_rows = cursor.fetchall()
        payment_methods = []
        for p in pay_rows:
            vol = float(p["total_volume"] or 0)
            payment_methods.append({
                "method": p["payment_method"].upper() if p.get("payment_method") else "OTHER",
                "count": int(p["usage_count"]),
                "volume": vol,
                "share": round((vol / max(1.0, gross_rev)) * 100, 1)
            })

        # -------------------------------------------------------------
        # 6. Order Status Breakdown
        # -------------------------------------------------------------
        status_sql = f"""
            SELECT o.status, COUNT(*) as count
            FROM orders o
            {date_where}
            GROUP BY o.status
        """
        cursor.execute(status_sql, date_params)
        status_rows = cursor.fetchall()
        order_statuses = {r["status"]: int(r["count"]) for r in status_rows}

        # -------------------------------------------------------------
        # 7. Recent High-Value Orders
        # -------------------------------------------------------------
        recent_sql = f"""
            SELECT 
                o.id, o.order_number, o.total_amount, o.status, 
                o.payment_method, o.payment_status, o.created_at,
                u.name as customer_name, u.email as customer_email
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            {date_where}
            ORDER BY o.created_at DESC
            LIMIT 5
        """
        cursor.execute(recent_sql, date_params)
        recent_rows = cursor.fetchall()
        recent_transactions = []
        for ro in recent_rows:
            recent_transactions.append({
                "id": ro["id"],
                "order_number": ro["order_number"],
                "total_amount": float(ro["total_amount"]),
                "status": ro["status"],
                "payment_method": ro["payment_method"],
                "payment_status": ro["payment_status"],
                "customer_name": ro.get("customer_name") or "Guest Customer",
                "customer_email": ro.get("customer_email") or "",
                "created_at": ro["created_at"].isoformat() if ro.get("created_at") else None
            })

        return jsonify({
            "success": True,
            "timeframe": timeframe,
            "kpis": {
                "gross_revenue": gross_rev,
                "net_revenue": net_rev,
                "total_discounts": total_discounts,
                "total_refunds": total_refunds,
                "average_order_value": aov,
                "total_orders": total_orders,
                "completed_orders": completed_orders,
                "cancelled_orders": cancelled_orders,
                "returned_orders": returned_orders,
                "total_units_sold": total_units,
                "active_buyers": active_buyers,
                "total_registered_customers": total_registered,
                "repeat_customer_rate": repeat_rate,
                "average_review_rating": avg_review_rating,
                "total_reviews": total_reviews
            },
            "chart_series": chart_series,
            "category_distribution": category_distribution,
            "top_products": top_products,
            "payment_methods": payment_methods,
            "order_statuses": order_statuses,
            "recent_transactions": recent_transactions
        }), 200
    except Exception as e:
        logging.error(f"Error compiling analytics: {e}")
        return jsonify({"success": False, "error": "Failed to compile business analytics"}), 500
    finally:
        cursor.close()
        conn.close()
