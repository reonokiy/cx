import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type VisibilityState,
} from "@tanstack/react-table"
import { Columns3, Inbox } from "lucide-react"
import { useState, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { cn } from "@/lib/utils"

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  loading?: boolean
  skeletonRows?: number
  emptyTitle?: string
  emptyDescription?: string
  emptyAction?: ReactNode
  toolbar?: ReactNode
  footer?: ReactNode
  enableColumnVisibility?: boolean
  columnLabels?: Record<string, string>
  initialColumnVisibility?: VisibilityState
  onRowClick?: (row: TData) => void
  selectedRowId?: (row: TData) => boolean
  className?: string
}

export function DataTable<TData, TValue>({
  columns,
  data,
  loading = false,
  skeletonRows = 6,
  emptyTitle = "暂无数据",
  emptyDescription = "当前筛选条件下没有匹配的记录。",
  emptyAction,
  toolbar,
  footer,
  enableColumnVisibility = false,
  columnLabels,
  initialColumnVisibility,
  onRowClick,
  selectedRowId,
  className,
}: DataTableProps<TData, TValue>) {
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(
    initialColumnVisibility ?? {}
  )

  const table = useReactTable({
    data,
    columns,
    state: { columnVisibility },
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
  })

  const hideableColumns = table
    .getAllColumns()
    .filter((column) => column.getCanHide())

  return (
    <div className={cn("min-w-0", className)}>
      {(toolbar || (enableColumnVisibility && hideableColumns.length > 0)) && (
        <div className="flex flex-wrap items-center justify-between gap-2.5 border-b px-4 py-3 sm:px-5">
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
            {toolbar}
          </div>
          {enableColumnVisibility && hideableColumns.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="h-8 gap-1.5">
                  <Columns3 className="size-3.5" />
                  <span>列显示</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-40">
                <DropdownMenuLabel>切换可见列</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {hideableColumns.map((column) => (
                  <DropdownMenuCheckboxItem
                    key={column.id}
                    checked={column.getIsVisible()}
                    onCheckedChange={(value) =>
                      column.toggleVisibility(Boolean(value))
                    }
                  >
                    {columnLabels?.[column.id] ?? column.id}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      )}

      {loading ? (
        <div role="status" className="space-y-2.5 px-4 py-5 sm:px-5">
          <span className="sr-only">正在加载…</span>
          {Array.from({ length: skeletonRows }).map((_, idx) => (
            <Skeleton key={idx} className="h-10 w-full rounded-md" />
          ))}
        </div>
      ) : table.getRowModel().rows.length === 0 ? (
        <Empty className="border-0 py-14">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <Inbox />
            </EmptyMedia>
            <EmptyTitle className="text-base">{emptyTitle}</EmptyTitle>
            <EmptyDescription>{emptyDescription}</EmptyDescription>
          </EmptyHeader>
          {emptyAction}
        </Empty>
      ) : (
        <Table>
          <TableHeader className="bg-muted/50 [&_th]:h-10 [&_th]:px-4 [&_th]:text-xs [&_th]:font-medium [&_th]:text-muted-foreground">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id} className="hover:bg-transparent">
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.map((row) => {
              const isSelected = selectedRowId?.(row.original) ?? false
              return (
                <TableRow
                  key={row.id}
                  data-state={isSelected ? "selected" : undefined}
                  onClick={
                    onRowClick ? () => onRowClick(row.original) : undefined
                  }
                  className={cn(
                    "[&_td]:px-4 [&_td]:py-2.5",
                    onRowClick && "cursor-pointer"
                  )}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      )}

      {footer && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-xs text-muted-foreground sm:px-5">
          {footer}
        </div>
      )}
    </div>
  )
}
